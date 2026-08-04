import hmac
import io
import re
import zipfile
from datetime import datetime
from typing import Annotated

from config import settings
from fastapi import APIRouter, Depends, Header, HTTPException, Query
from fastapi.responses import StreamingResponse
from pydantic import BaseModel, Field, constr, field_validator, model_validator

from . import service

api = APIRouter(prefix='/admin', tags=['admin'])


class AdminApiKey:
    def __call__(self, api_key: Annotated[str | None, Header(alias='X-Admin-API-Key')] = None):
        expected = settings.admin.api_key.get_secret_value() if settings.admin.api_key else ''
        if not api_key or not hmac.compare_digest(api_key, expected):
            raise HTTPException(status_code=403, detail='Forbidden')


require_admin_key = AdminApiKey()


class IssueRequest(BaseModel):
    domains: Annotated[list[str], Field(min_length=1)]
    key_type: str = 'rsa'
    key_size: int = 2048

    @model_validator(mode='after')
    def validate_key(self):
        if self.key_type not in ('rsa', 'ec'):
            raise ValueError('key_type must be "rsa" or "ec"')
        if self.key_type == 'rsa' and self.key_size not in (2048, 4096):
            raise ValueError('RSA key_size must be 2048 or 4096')
        if self.key_type == 'ec' and self.key_size not in (256, 384):
            raise ValueError('EC key_size must be 256 or 384')
        return self

    @field_validator('domains')
    @classmethod
    def validate_domains(cls, domains):
        for domain in domains:
            if not re.fullmatch(settings.acme.target_domain_regex, domain):
                raise ValueError(f'domain {domain} does not match ACME_TARGET_DOMAIN_REGEX')
        return domains


class IssueResponse(BaseModel):
    model_config = {'extra': 'ignore'}
    private_key: str
    certificate: str
    chain: str
    serial_number: str
    not_before: datetime
    not_after: datetime


class RevokeRequest(BaseModel):
    serial_number: constr(pattern='^[0-9A-F]+$')  # type: ignore[valid-type]


@api.post('/issue', response_model=IssueResponse)
async def issue(
    request: IssueRequest,
    _: Annotated[None, Depends(require_admin_key)],
    download: Annotated[bool, Query()] = False,
):
    cert = await service.issue_certificate(
        domains=request.domains,
        key_type=request.key_type,
        key_size=request.key_size,
    )
    if not download:
        return cert

    zip_buffer = io.BytesIO()
    with zipfile.ZipFile(zip_buffer, 'w', zipfile.ZIP_DEFLATED) as zip_file:
        zip_file.writestr(f'{request.domains[0]}.key', cert['private_key'])
        zip_file.writestr(f'{request.domains[0]}.crt', cert['certificate'])
        zip_file.writestr('chain.crt', cert['chain'])
    zip_buffer.seek(0)

    return StreamingResponse(
        zip_buffer,
        media_type='application/zip',
        headers={'Content-Disposition': f'attachment; filename="{request.domains[0]}.zip"'},
    )


@api.get('/certificates/{serial_number}', responses={200: {'content': {'application/zip'}}})
async def download_certificate(
    serial_number: constr(pattern='^[0-9A-F]+$'),  # type: ignore[valid-type]
    _: Annotated[None, Depends(require_admin_key)],
):
    cert = await service.load_certificate_with_key(serial_number)

    zip_buffer = io.BytesIO()
    with zipfile.ZipFile(zip_buffer, 'w', zipfile.ZIP_DEFLATED) as zip_file:
        zip_file.writestr(f'{cert["first_domain"]}.key', cert['private_key'])
        zip_file.writestr(f'{cert["first_domain"]}.crt', cert['certificate'])
        zip_file.writestr('chain.crt', cert['chain'])
    zip_buffer.seek(0)

    return StreamingResponse(
        zip_buffer,
        media_type='application/zip',
        headers={'Content-Disposition': f'attachment; filename="{cert["first_domain"]}.zip"'},
    )


@api.post('/revoke')
async def revoke(
    request: RevokeRequest,
    _: Annotated[None, Depends(require_admin_key)],
):
    await service.revoke_certificate(request.serial_number)
    return {'revoked': True}
