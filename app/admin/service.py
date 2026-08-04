import asyncio
import secrets

from acme.certificate.service import SerialNumberConverter
from ca import service as ca_service
from config import settings
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from fastapi import HTTPException, status

import db

ADMIN_ACCOUNT_ID = 'internal_admin_account_0000000000'
ADMIN_ACCOUNT_JWK = {'kty': 'admin'}


def _generate_private_key(key_type: str, key_size: int):
    if key_type == 'rsa':
        return rsa.generate_private_key(public_exponent=65537, key_size=key_size)
    curve = ec.SECP256R1() if key_size == 256 else ec.SECP384R1()
    return ec.generate_private_key(curve=curve)


def _generate_csr(private_key, domains: list[str]):
    return (
        x509.CertificateSigningRequestBuilder()
        .subject_name(x509.Name([x509.NameAttribute(x509.NameOID.COMMON_NAME, domains[0])]))
        .add_extension(x509.SubjectAlternativeName([x509.DNSName(domain) for domain in domains]), critical=False)
        .sign(private_key, hashes.SHA256())
    )


async def init():
    if not settings.admin.api_key:
        return
    async with db.transaction() as sql:
        await sql.exec(
            """
            insert into accounts (id, mail, jwk, status)
            values ($1, null, $2, 'deactivated')
            on conflict (id) do nothing
            """,
            ADMIN_ACCOUNT_ID,
            ADMIN_ACCOUNT_JWK,
        )


async def issue_certificate(domains: list[str], key_type: str, key_size: int):
    if not settings.ca.enabled:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail='internal CA is not enabled')

    private_key = await asyncio.to_thread(_generate_private_key, key_type, key_size)
    csr = await asyncio.to_thread(_generate_csr, private_key, domains)

    private_key_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode()
    csr_pem = csr.public_bytes(serialization.Encoding.PEM).decode()

    order_id = secrets.token_urlsafe(16)
    authz_ids = {domain: secrets.token_urlsafe(16) for domain in domains}
    chal_id = secrets.token_urlsafe(16)
    token = secrets.token_urlsafe(32)

    signed_cert = await ca_service.sign_csr(csr, domains[0], domains)
    cert_sn = SerialNumberConverter.int2hex(signed_cert.cert.serial_number)

    async with db.transaction() as sql:
        await sql.exec(
            """insert into orders (id, account_id, status) values ($1, $2, 'valid')""",
            order_id,
            ADMIN_ACCOUNT_ID,
        )
        await sql.execmany(
            """insert into authorizations (id, order_id, domain, status) values ($1, $2, $3, 'valid')""",
            *[(authz_ids[domain], order_id, domain) for domain in domains],
        )
        await sql.exec(
            """
            insert into challenges (id, authz_id, token, status, type, validated_at)
            values ($1, $2, $3, 'valid', 'http-01', now())
            """,
            chal_id,
            authz_ids[domains[0]],
            token,
        )
        await sql.exec(
            """
            insert into certificates (serial_number, csr_pem, chain_pem, private_key_pem, order_id, not_valid_before, not_valid_after)
            values ($1, $2, $3, $4, $5, $6, $7)
            """,
            cert_sn,
            csr_pem,
            signed_cert.cert_chain_pem,
            private_key_pem,
            order_id,
            signed_cert.cert.not_valid_before_utc,
            signed_cert.cert.not_valid_after_utc,
        )

    return {
        'private_key': private_key_pem,
        'certificate': signed_cert.cert.public_bytes(serialization.Encoding.PEM).decode(),
        'chain': signed_cert.cert_chain_pem,
        'serial_number': cert_sn,
        'not_before': signed_cert.cert.not_valid_before_utc,
        'not_after': signed_cert.cert.not_valid_after_utc,
    }


async def load_certificate_with_key(serial_number: str):
    async with db.transaction(readonly=True) as sql:
        record = await sql.record(
            """
            select cert.chain_pem, cert.private_key_pem,
                   (select array_agg(domain order by domain) from authorizations where order_id = cert.order_id) as domains
            from certificates cert
            where cert.serial_number = $1
            """,
            serial_number,
        )
    if not record or not record['private_key_pem']:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail='certificate or private key not found')

    chain_pem = record['chain_pem'].encode()
    certificate = x509.load_pem_x509_certificates(chain_pem)[0]
    return {
        'private_key': record['private_key_pem'],
        'certificate': certificate.public_bytes(serialization.Encoding.PEM).decode(),
        'chain': record['chain_pem'],
        'first_domain': record['domains'][0] if record['domains'] else serial_number,
    }


async def delete_certificate(serial_number: str):
    async with db.transaction(readonly=True) as sql:
        record = await sql.record(
            """select order_id, (revoked_at is not null) as is_revoked from certificates where serial_number = $1""",
            serial_number,
        )
    if not record:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail='certificate not found')

    order_id = record['order_id']
    is_revoked = record['is_revoked']

    async with db.transaction() as sql:
        await sql.exec(
            """delete from challenges where authz_id in (select id from authorizations where order_id = $1)""",
            order_id,
        )
        await sql.exec("""delete from authorizations where order_id = $1""", order_id)
        await sql.exec("""delete from certificates where serial_number = $1""", serial_number)
        await sql.exec("""delete from orders where id = $1""", order_id)

    if is_revoked:
        async with db.transaction(readonly=True) as sql:
            revocations = {(row['serial_number'], row['revoked_at']) async for row in sql("""select serial_number, revoked_at from certificates where revoked_at is not null""")}
        await ca_service.revoke_cert(serial_number=serial_number, revocations=revocations)


async def revoke_certificate(serial_number: str):
    async with db.transaction(readonly=True) as sql:
        exists = await sql.value("""select 1 from certificates where serial_number = $1""", serial_number)
    if not exists:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail='certificate not found')

    async with db.transaction() as sql:
        revoked_at = await sql.value("""select now()""")
        result = await sql.exec(
            """update certificates set revoked_at = $1 where serial_number = $2 and revoked_at is null""",
            revoked_at,
            serial_number,
        )
    if result == 'UPDATE 0':
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail='certificate already revoked')

    async with db.transaction(readonly=True) as sql:
        revocations = {(row['serial_number'], row['revoked_at']) async for row in sql("""select serial_number, revoked_at from certificates where revoked_at is not null""")}
    await ca_service.revoke_cert(serial_number=serial_number, revocations=revocations)
