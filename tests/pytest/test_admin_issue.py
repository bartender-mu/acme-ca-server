import zipfile
from io import BytesIO
from unittest import mock

import httpx
import jwcrypto.common
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa

from .utils import build_csr

_mail_address = 'mailto:dummy@example.com'
_host = 'example.com'


def _issue_admin_certificate(testclient, domain='db.example.org'):
    response = testclient.post(
        '/admin/issue',
        headers={'X-Admin-API-Key': 'test-admin-key'},
        json={'domains': [domain], 'key_type': 'rsa', 'key_size': 2048},
    )
    assert response.status_code == 200
    return response.json()


def _issue_acme_certificate(signed_request, directory):
    response = signed_request(directory['newAccount'], signed_request.nonce, {'contact': [_mail_address]})
    account_id = response.headers['Location']

    response = signed_request(directory['newOrder'], response.headers['Replay-Nonce'], {'identifiers': [{'type': 'dns', 'value': _host}]}, account_id)
    authz_url = response.json()['authorizations'][0]
    finalize_order_url = response.json()['finalize']

    response = signed_request(authz_url, response.headers['Replay-Nonce'], '', account_id)
    challenge_token = response.json()['challenges'][0]['token']
    challenge_url = response.json()['challenges'][0]['url']

    mock_challenge_file_contents = f'{challenge_token}.{signed_request.account_jwk.thumbprint()}'.rstrip()
    with mock.patch(
        'acme.challenge.service.httpx.AsyncClient.get',
        return_value=httpx.Response(200, text=mock_challenge_file_contents),
    ) as mock_get:
        response = signed_request(challenge_url, response.headers['Replay-Nonce'], '', account_id)

    mock_get.assert_called_once_with(f'http://{_host}:80/.well-known/acme-challenge/{challenge_token}')

    csr = build_csr([_host])
    response = signed_request(
        finalize_order_url, response.headers['Replay-Nonce'], {'csr': jwcrypto.common.base64url_encode(csr.public_bytes(serialization.Encoding.DER))}, account_id
    )
    cert_url = response.json()['certificate']

    response = signed_request(cert_url, response.headers['Replay-Nonce'], {}, account_id)
    return x509.load_pem_x509_certificate(response.content)


def test_admin_issue_rsa_2048(testclient):
    response = testclient.post(
        '/admin/issue',
        headers={'X-Admin-API-Key': 'test-admin-key'},
        json={'domains': ['db.example.org'], 'key_type': 'rsa', 'key_size': 2048},
    )
    assert response.status_code == 200
    data = response.json()
    _assert_issue_response(data, 'db.example.org')
    private_key = serialization.load_pem_private_key(data['private_key'].encode(), None)
    assert isinstance(private_key, rsa.RSAPrivateKey)
    assert private_key.key_size == 2048


def test_admin_issue_rsa_4096(testclient):
    response = testclient.post(
        '/admin/issue',
        headers={'X-Admin-API-Key': 'test-admin-key'},
        json={'domains': ['db.example.org'], 'key_type': 'rsa', 'key_size': 4096},
    )
    assert response.status_code == 200
    data = response.json()
    _assert_issue_response(data, 'db.example.org')
    private_key = serialization.load_pem_private_key(data['private_key'].encode(), None)
    assert isinstance(private_key, rsa.RSAPrivateKey)
    assert private_key.key_size == 4096


def test_admin_issue_ec_256(testclient):
    response = testclient.post(
        '/admin/issue',
        headers={'X-Admin-API-Key': 'test-admin-key'},
        json={'domains': ['db.example.org'], 'key_type': 'ec', 'key_size': 256},
    )
    assert response.status_code == 200
    data = response.json()
    _assert_issue_response(data, 'db.example.org')
    private_key = serialization.load_pem_private_key(data['private_key'].encode(), None)
    assert isinstance(private_key, ec.EllipticCurvePrivateKey)
    assert private_key.curve.name == 'secp256r1'


def test_admin_issue_rejects_invalid_key_size(testclient):
    response = testclient.post(
        '/admin/issue',
        headers={'X-Admin-API-Key': 'test-admin-key'},
        json={'domains': ['db.example.org'], 'key_type': 'rsa', 'key_size': 1024},
    )
    assert response.status_code == 422


def test_admin_issue_requires_api_key(testclient):
    response = testclient.post(
        '/admin/issue',
        json={'domains': ['db.example.org']},
    )
    assert response.status_code == 403

    response = testclient.post(
        '/admin/issue',
        headers={'X-Admin-API-Key': 'wrong-key'},
        json={'domains': ['db.example.org']},
    )
    assert response.status_code == 403


def test_admin_revoke_certificate(testclient, db):
    response = testclient.post(
        '/admin/issue',
        headers={'X-Admin-API-Key': 'test-admin-key'},
        json={'domains': ['db.example.org'], 'key_type': 'rsa', 'key_size': 2048},
    )
    assert response.status_code == 200
    serial_number = response.json()['serial_number']

    response = testclient.post(
        '/admin/revoke',
        headers={'X-Admin-API-Key': 'test-admin-key'},
        json={'serial_number': serial_number},
    )
    assert response.status_code == 200

    record = db.fetch_row('select revoked_at from certificates where serial_number = $1', serial_number)
    assert record is not None
    assert record['revoked_at'] is not None


def test_admin_issue_stores_private_key(testclient, db):
    data = _issue_admin_certificate(testclient)
    serial_number = data['serial_number']

    record = db.fetch_row('select private_key_pem from certificates where serial_number = $1', serial_number)
    assert record is not None
    assert record['private_key_pem'] is not None
    assert record['private_key_pem'].startswith('-----BEGIN PRIVATE KEY-----')


def test_admin_download_certificate(testclient):
    data = _issue_admin_certificate(testclient, domain='download.example.org')
    serial_number = data['serial_number']

    response = testclient.get(
        f'/admin/certificates/{serial_number}',
        headers={'X-Admin-API-Key': 'test-admin-key'},
    )
    assert response.status_code == 200
    assert response.headers['Content-Type'] == 'application/zip'

    with zipfile.ZipFile(BytesIO(response.content)) as zip_file:
        names = zip_file.namelist()
        assert 'download.example.org.key' in names
        assert 'download.example.org.crt' in names
        assert 'chain.crt' in names
        assert zip_file.read('download.example.org.key').startswith(b'-----BEGIN PRIVATE KEY-----')
        assert zip_file.read('download.example.org.crt').startswith(b'-----BEGIN CERTIFICATE-----')


def test_admin_download_certificate_requires_api_key(testclient):
    data = _issue_admin_certificate(testclient)
    serial_number = data['serial_number']

    response = testclient.get(f'/admin/certificates/{serial_number}')
    assert response.status_code == 403

    response = testclient.get(
        f'/admin/certificates/{serial_number}',
        headers={'X-Admin-API-Key': 'wrong-key'},
    )
    assert response.status_code == 403


def test_admin_download_certificate_not_found_for_acme_cert(signed_request, directory, testclient):
    acme_cert = _issue_acme_certificate(signed_request, directory)
    serial_number = f'{acme_cert.serial_number:X}'

    response = testclient.get(
        f'/admin/certificates/{serial_number}',
        headers={'X-Admin-API-Key': 'test-admin-key'},
    )
    assert response.status_code == 404


def test_admin_revoke_acme_certificate(signed_request, directory, testclient, db):
    acme_cert = _issue_acme_certificate(signed_request, directory)
    serial_number = f'{acme_cert.serial_number:X}'

    response = testclient.post(
        '/admin/revoke',
        headers={'X-Admin-API-Key': 'test-admin-key'},
        json={'serial_number': serial_number},
    )
    assert response.status_code == 200

    record = db.fetch_row('select revoked_at from certificates where serial_number = $1', serial_number)
    assert record is not None
    assert record['revoked_at'] is not None


def test_admin_delete_certificate(testclient, db):
    data = _issue_admin_certificate(testclient, domain='delete.example.org')
    serial_number = data['serial_number']
    order_id = db.fetch_row('select order_id from certificates where serial_number = $1', serial_number)['order_id']

    response = testclient.post(
        '/admin/delete',
        headers={'X-Admin-API-Key': 'test-admin-key'},
        json={'serial_number': serial_number},
    )
    assert response.status_code == 200

    assert db.fetch_row('select 1 from certificates where serial_number = $1', serial_number) is None
    assert db.fetch_row('select 1 from orders where id = $1', order_id) is None
    assert db.fetch_row('select 1 from authorizations where order_id = $1', order_id) is None
    assert db.fetch_row('select 1 from challenges where authz_id in (select id from authorizations where order_id = $1)', order_id) is None


def test_admin_delete_revoked_certificate(testclient, db):
    data = _issue_admin_certificate(testclient, domain='deleterevoked.example.org')
    serial_number = data['serial_number']

    response = testclient.post(
        '/admin/revoke',
        headers={'X-Admin-API-Key': 'test-admin-key'},
        json={'serial_number': serial_number},
    )
    assert response.status_code == 200

    response = testclient.post(
        '/admin/delete',
        headers={'X-Admin-API-Key': 'test-admin-key'},
        json={'serial_number': serial_number},
    )
    assert response.status_code == 200
    assert db.fetch_row('select 1 from certificates where serial_number = $1', serial_number) is None


def test_admin_delete_requires_api_key(testclient):
    data = _issue_admin_certificate(testclient)
    serial_number = data['serial_number']

    response = testclient.post('/admin/delete', json={'serial_number': serial_number})
    assert response.status_code == 403

    response = testclient.post(
        '/admin/delete',
        headers={'X-Admin-API-Key': 'wrong-key'},
        json={'serial_number': serial_number},
    )
    assert response.status_code == 403


def test_admin_delete_not_found(testclient):
    response = testclient.post(
        '/admin/delete',
        headers={'X-Admin-API-Key': 'test-admin-key'},
        json={'serial_number': 'ABCDEF'},
    )
    assert response.status_code == 404


def _assert_issue_response(data, expected_domain):
    assert 'private_key' in data
    assert 'certificate' in data
    assert 'chain' in data
    assert 'serial_number' in data
    assert 'not_before' in data
    assert 'not_after' in data

    cert = x509.load_pem_x509_certificate(data['certificate'].encode())
    sans = cert.extensions.get_extension_for_oid(x509.oid.ExtensionOID.SUBJECT_ALTERNATIVE_NAME).value.get_values_for_type(x509.DNSName)
    assert expected_domain in sans

    chain = x509.load_pem_x509_certificates(data['chain'].encode())
    assert len(chain) >= 2
    assert chain[0] == cert

    # sanity-check the public key in the certificate matches the private key
    private_key = serialization.load_pem_private_key(data['private_key'].encode(), None)
    assert cert.public_key() == private_key.public_key()
