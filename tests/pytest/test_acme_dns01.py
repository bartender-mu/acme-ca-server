import base64
import hashlib
from unittest import mock

import jwcrypto.common
import pytest
from cryptography import x509
from cryptography.hazmat.primitives.serialization import Encoding

from .utils import build_csr

_mail_address = 'mailto:dummy@example.com'
_host = 'dns01.example.org'


def _key_authorization_digest(token: str, thumbprint: str) -> str:
    key_authorization = f'{token}.{thumbprint}'
    digest = hashlib.sha256(key_authorization.encode()).digest()
    return base64.urlsafe_b64encode(digest).rstrip(b'=').decode()


@pytest.fixture
def enable_dns01(monkeypatch):
    import config

    monkeypatch.setattr(config.settings.acme, 'dns01_enabled', True)
    monkeypatch.setattr(config.settings.acme, 'http01_enabled', True)
    monkeypatch.setattr(config.settings.acme, 'dns01_max_retries', 2)
    monkeypatch.setattr(config.settings.acme, 'dns01_retry_delay_seconds', 0)


def test_order_returns_dns01_and_http01_challenge(signed_request, directory, enable_dns01):
    response = signed_request(directory['newAccount'], signed_request.nonce, {'contact': [_mail_address]})
    account_id = response.headers['Location']

    response = signed_request(directory['newOrder'], response.headers['Replay-Nonce'], {'identifiers': [{'type': 'dns', 'value': _host}]}, account_id)
    authz_url = response.json()['authorizations'][0]

    response = signed_request(authz_url, response.headers['Replay-Nonce'], '', account_id)
    challenges = response.json()['challenges']
    types = [chal['type'] for chal in challenges]
    assert 'http-01' in types
    assert 'dns-01' in types


def test_dns01_challenge_can_issue_certificate(signed_request, directory, enable_dns01, monkeypatch):
    response = signed_request(directory['newAccount'], signed_request.nonce, {'contact': [_mail_address]})
    account_id = response.headers['Location']

    response = signed_request(directory['newOrder'], response.headers['Replay-Nonce'], {'identifiers': [{'type': 'dns', 'value': _host}]}, account_id)
    authz_url = response.json()['authorizations'][0]
    finalize_order_url = response.json()['finalize']

    response = signed_request(authz_url, response.headers['Replay-Nonce'], '', account_id)
    challenges = response.json()['challenges']
    dns_challenge = next(chal for chal in challenges if chal['type'] == 'dns-01')
    challenge_url = dns_challenge['url']
    challenge_token = dns_challenge['token']

    expected_digest = _key_authorization_digest(challenge_token, signed_request.account_jwk.thumbprint())
    txt_records = {_host: expected_digest}

    async def set_txt_record(name: str, value: str, ttl: int):
        txt_records[_host] = value

    async def remove_txt_record(name: str, value: str):
        txt_records.pop(_host, None)

    def resolve_txt_record(record_name: str):
        return [txt_records.get(_host, '')]

    monkeypatch.setattr('acme.challenge.dns_provider.set_txt_record', set_txt_record)
    monkeypatch.setattr('acme.challenge.dns_provider.remove_txt_record', remove_txt_record)
    monkeypatch.setattr('acme.challenge.service._resolve_txt_record', resolve_txt_record)

    response = signed_request(challenge_url, response.headers['Replay-Nonce'], '', account_id)
    assert response.status_code == 200
    assert response.json()['status'] == 'valid'

    csr = build_csr([_host])
    response = signed_request(
        finalize_order_url,
        response.headers['Replay-Nonce'],
        {'csr': jwcrypto.common.base64url_encode(csr.public_bytes(Encoding.DER))},
        account_id,
    )
    assert response.status_code == 200
    cert_url = response.json()['certificate']

    response = signed_request(cert_url, response.headers['Replay-Nonce'], {}, account_id)
    signed_cert = x509.load_pem_x509_certificate(response.content)
    assert signed_cert.subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME)[0].value == _host
    assert signed_cert.public_key() == csr.public_key()


def test_dns01_challenge_fails_when_txt_record_missing(signed_request, directory, enable_dns01, monkeypatch):
    response = signed_request(directory['newAccount'], signed_request.nonce, {'contact': [_mail_address]})
    account_id = response.headers['Location']

    response = signed_request(directory['newOrder'], response.headers['Replay-Nonce'], {'identifiers': [{'type': 'dns', 'value': _host}]}, account_id)
    authz_url = response.json()['authorizations'][0]

    response = signed_request(authz_url, response.headers['Replay-Nonce'], '', account_id)
    dns_challenge = next(chal for chal in response.json()['challenges'] if chal['type'] == 'dns-01')
    challenge_url = dns_challenge['url']

    async def set_txt_record(name: str, value: str, ttl: int):
        pass

    async def remove_txt_record(name: str, value: str):
        pass

    monkeypatch.setattr('acme.challenge.dns_provider.set_txt_record', set_txt_record)
    monkeypatch.setattr('acme.challenge.dns_provider.remove_txt_record', remove_txt_record)
    monkeypatch.setattr('acme.challenge.service._resolve_txt_record', lambda name: [])

    with mock.patch('acme.challenge.service.logger'):
        response = signed_request(challenge_url, response.headers['Replay-Nonce'], '', account_id)

    assert response.status_code == 200
    assert response.json()['status'] == 'invalid'
    assert response.json()['error']['type'] == 'urn:ietf:params:acme:error:incorrectResponse'
