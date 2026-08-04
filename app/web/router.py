from pathlib import Path
from typing import Literal

from config import settings
from fastapi import APIRouter, HTTPException, Request, Response, status
from fastapi.responses import HTMLResponse, RedirectResponse
from jinja2 import Environment, FileSystemLoader
from pydantic import constr

import db

template_engine = Environment(loader=FileSystemLoader(Path(__file__).parent / 'templates'), enable_async=True, autoescape=True)

_ASSET_VERSION = str(int(max(Path(__file__).parent.joinpath('www', name).stat().st_mtime for name in ('admin.js', 'issue.js'))))

default_params = {
    'app_title': settings.web.app_title,
    'app_desc': settings.web.app_description,
    'web_url': str(settings.external_url),
    'acme_url': str(settings.external_url).removesuffix('/') + '/acme/directory',
    'admin_enabled': settings.admin.api_key is not None,
    'asset_version': _ASSET_VERSION,
}


def _session_params(request: Request) -> dict:
    user = getattr(request.state, 'user', None)
    if user:
        return {
            'user_username': user.username,
            'user_group': user.group_name,
            'user_is_admin': user.group_name == 'admin',
        }
    return {'user_username': None, 'user_group': None, 'user_is_admin': False}


api = APIRouter(tags=['web'])


@api.get('/', response_class=HTMLResponse)
async def index(request: Request):
    params = {**default_params, **_session_params(request)}
    return await template_engine.get_template('index.html').render_async(**params)


@api.get('/issue', response_class=HTMLResponse)
async def issue_page(request: Request):
    user = getattr(request.state, 'user', None)
    if not user or user.group_name != 'admin':
        return RedirectResponse(url='/login', status_code=303)
    params = {**default_params, **_session_params(request)}
    return await template_engine.get_template('issue-cert.html').render_async(**params)


if settings.web.enable_public_log:

    @api.get('/certificates', response_class=HTMLResponse)
    async def certificate_log(request: Request, domainfilter: str = '', certstatus: Literal['all', 'valid', 'invalid'] = 'all'):
        params = {**default_params, **_session_params(request)}
        async with db.transaction(readonly=True) as sql:
            certs = [
                record
                async for record in sql(
                    """
                    with data as (
                        select
                            serial_number, not_valid_before, not_valid_after, revoked_at,
                            (not_valid_after > now() and revoked_at is null) as is_valid,
                            (not_valid_after - not_valid_before) as lifetime,
                            (now() - not_valid_before) as age,
                            (cert.private_key_pem is not null) as has_private_key,
                            array_agg(domain order by domain) as domains
                        from certificates cert
                        join authorizations authz on authz.order_id = cert.order_id
                        where ($1::text = '' or authz.domain ilike '%' || $1::text || '%')
                        group by serial_number, cert.private_key_pem
                    )
                    select * from data
                    where ($2 = 'all' or ($2 = 'valid' and is_valid) or ($2 = 'invalid' and not is_valid))
                    order by not_valid_after desc
                    limit 1000
                    """,
                    domainfilter.replace('*', '%'),
                    certstatus,
                )
            ]
        return await template_engine.get_template('cert-log.html').render_async(**params, certs=certs, certstatus=certstatus, domainfilter=domainfilter)

    @api.get('/certificates/{serial_number}', response_class=Response, responses={200: {'content': {'application/pem-certificate-chain': {}}}})
    async def download_certificate(serial_number: constr(pattern='^[0-9A-F]+$')):  # type: ignore[valid-type]
        async with db.transaction(readonly=True) as sql:
            pem_chain = await sql.value("""select chain_pem from certificates where serial_number = $1""", serial_number)
        if not pem_chain:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail='unknown certificate')
        return Response(
            content=pem_chain,
            media_type='application/pem-certificate-chain',
            headers={'Content-Disposition': f'attachment; filename="{serial_number}.crt"'},
        )

    @api.get('/domains', response_class=HTMLResponse)
    async def domain_log(request: Request, domainfilter: str = '', domainstatus: Literal['all', 'valid', 'invalid'] = 'all'):
        params = {**default_params, **_session_params(request)}
        async with db.transaction(readonly=True) as sql:
            domains = [
                record
                async for record in sql(
                    """
                    with data as (
                        select
                            authz.domain as domain_name,
                            min(cert.not_valid_before) as first_requested_at,
                            max(cert.not_valid_after) as expires_at,
                            (max(cert.not_valid_after) FILTER (WHERE revoked_at is null)) > now() AS is_valid
                        from orders ord
                        join authorizations authz on authz.order_id = ord.id
                        join certificates cert on cert.order_id = ord.id
                        where ($1::text = '' or authz.domain ilike '%' || $1::text || '%')
                        group by authz.domain
                    )
                    select * from data
                    where ($2 = 'all' or ($2 = 'valid' and is_valid) or ($2 = 'invalid' and not is_valid))
                    order by domain_name
                    """,
                    domainfilter.replace('*', '%'),
                    domainstatus,
                )
            ]
        return await template_engine.get_template('domain-log.html').render_async(**params, domains=domains, domainstatus=domainstatus, domainfilter=domainfilter)
else:

    @api.get('/certificates')
    async def certificate_log_disabled():
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail='This page is disabled')

    @api.get('/domains')
    async def domain_log_disabled():
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail='This page is disabled')
