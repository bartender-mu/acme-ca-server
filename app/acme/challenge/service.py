import asyncio
import base64
import hashlib
from typing import Literal

import dns.rdatatype
import dns.resolver
import httpx
import jwcrypto.jwk
from config import settings
from fastapi import status
from logger import logger

from ..exceptions import ACMEException
from . import dns_provider


def _key_authorization_digest(token: str, jwk: jwcrypto.jwk.JWK) -> str:
    key_authorization = f'{token}.{jwk.thumbprint()}'
    digest = hashlib.sha256(key_authorization.encode()).digest()
    return base64.urlsafe_b64encode(digest).rstrip(b'=').decode()


def _dns_txt_record(domain: str) -> str:
    return f'_acme-challenge.{domain}'


def _resolve_txt_record(record_name: str) -> list[str]:
    resolver = dns.resolver.Resolver()
    if settings.acme.dns01_nameservers:
        resolver.nameservers = [ns.strip() for ns in settings.acme.dns01_nameservers.split(',') if ns.strip()]
    answers = resolver.resolve(record_name, dns.rdatatype.TXT)
    values = []
    for rdata in answers:
        values.append(b''.join(rdata.strings).decode())  # type: ignore[attr-defined]
    return values


async def check_challenge_is_fulfilled(*, domain: str, token: str, jwk: jwcrypto.jwk.JWK, new_nonce: str | None = None):
    for _ in range(3):  # 3x retry
        err: Literal[False] | ACMEException
        try:
            async with httpx.AsyncClient(
                timeout=10,
                # only http 1.0/1.1 is required, not https
                verify=False,
                http1=True,
                http2=False,
                # todo: redirects are forbidden for now, but RFC states redirects should be supported
                follow_redirects=False,
                trust_env=False,  # do not load proxy information from env vars
            ) as client:
                res = await client.get(f'http://{domain}:80/.well-known/acme-challenge/{token}')
                if res.status_code == 200 and res.text.rstrip() == f'{token}.{jwk.thumbprint()}':
                    err = False
                else:
                    err = ACMEException(
                        status_code=status.HTTP_400_BAD_REQUEST,
                        exctype='incorrectResponse',
                        detail='presented token does not match challenge',
                        new_nonce=new_nonce,
                    )
        except httpx.ConnectTimeout:
            err = ACMEException(status_code=status.HTTP_400_BAD_REQUEST, exctype='connection', detail='timeout', new_nonce=new_nonce)
        except httpx.ConnectError:
            err = ACMEException(status_code=status.HTTP_400_BAD_REQUEST, exctype='dns', detail='could not resolve address', new_nonce=new_nonce)
        except Exception:
            err = ACMEException(status_code=status.HTTP_400_BAD_REQUEST, exctype='serverInternal', detail='could not validate challenge', new_nonce=new_nonce)
        if err is False:
            return  # check successful
        await asyncio.sleep(3)
    raise err  # type: ignore[misc]


async def check_dns_challenge_is_fulfilled(*, domain: str, token: str, jwk: jwcrypto.jwk.JWK, new_nonce: str | None = None):
    digest = _key_authorization_digest(token, jwk)
    record_name = _dns_txt_record(domain)

    try:
        await dns_provider.set_txt_record(record_name, digest, settings.acme.dns01_ttl)
    except Exception as exc:
        raise ACMEException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            exctype='serverInternal',
            detail=f'could not set DNS TXT record: {exc}',
            new_nonce=new_nonce,
        ) from exc

    try:
        for attempt in range(settings.acme.dns01_max_retries):
            try:
                txt_values = await asyncio.to_thread(_resolve_txt_record, record_name)
            except dns.resolver.NoAnswer:
                if attempt + 1 == settings.acme.dns01_max_retries:
                    raise ACMEException(
                        status_code=status.HTTP_400_BAD_REQUEST,
                        exctype='incorrectResponse',
                        detail='DNS TXT record not found',
                        new_nonce=new_nonce,
                    )
                await asyncio.sleep(settings.acme.dns01_retry_delay_seconds)
                continue
            except dns.resolver.NXDOMAIN:
                if attempt + 1 == settings.acme.dns01_max_retries:
                    raise ACMEException(
                        status_code=status.HTTP_400_BAD_REQUEST,
                        exctype='dns',
                        detail=f'could not resolve {record_name}',
                        new_nonce=new_nonce,
                    )
                await asyncio.sleep(settings.acme.dns01_retry_delay_seconds)
                continue
            except Exception as exc:
                raise ACMEException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    exctype='dns',
                    detail=f'could not resolve DNS TXT record: {exc}',
                    new_nonce=new_nonce,
                ) from exc
            if digest in txt_values:
                return  # validation successful
            if attempt + 1 == settings.acme.dns01_max_retries:
                raise ACMEException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    exctype='incorrectResponse',
                    detail='DNS TXT record does not match challenge',
                    new_nonce=new_nonce,
                )
            await asyncio.sleep(settings.acme.dns01_retry_delay_seconds)
    finally:
        try:
            await dns_provider.remove_txt_record(record_name, digest)
        except Exception:
            logger.warning('could not remove DNS TXT record %s', record_name, exc_info=True)
