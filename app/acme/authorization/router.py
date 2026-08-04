from typing import Annotated, Literal, Optional

from config import settings
from fastapi import APIRouter, Depends, status
from pydantic import BaseModel

import db

from ..exceptions import ACMEException
from ..middleware import RequestData, SignedRequest


class UpdateAuthzPayload(BaseModel):
    status: Literal['deactivated'] | None = None


api = APIRouter(tags=['acme:authorization'])


@api.post('/authorizations/{authz_id}')
async def view_or_update_authorization(
    authz_id: str,
    data: Annotated[RequestData[UpdateAuthzPayload | None], Depends(SignedRequest(Optional[UpdateAuthzPayload]))],
):
    async with db.transaction(readonly=True) as sql:
        record = await sql.record(
            """
            select authz.status, ord.status, ord.expires_at, authz.domain
            from authorizations authz
            join orders ord on authz.order_id = ord.id
            where authz.id = $1 and ord.account_id = $2
            """,
            authz_id,
            data.account_id,
        )
        challenges = [
            row
            async for row in sql(
                """select id, token, status, type, validated_at from challenges where authz_id = $1""",
                authz_id,
            )
        ]
    if record:
        authz_status, order_status, expires_at, domain = record
        if data.payload and data.payload.status == 'deactivated':  # deactivate authz
            if authz_status in ['pending', 'valid'] and order_status in ['pending', 'ready']:
                async with db.transaction() as sql:
                    await sql.exec(
                        """
                        update orders set status='invalid', error=row('unauthorized','authorization deactivated')
                        where id = (select order_id from authorizations where id = $1)
                        """,
                        authz_id,
                    )
                    authz_status = await sql.value("""update authorizations set status = 'deactivated' where id = $1 returning status""", authz_id)
        challenges_list = [
            {
                k: v
                for k, v in {
                    'type': ch_type,
                    'url': f'{settings.external_url}acme/challenges/{ch_id}',
                    'token': ch_token,
                    'status': ch_status,
                    'validated': chal_validated_at,
                }.items()
                if v is not None
            }
            for ch_id, ch_token, ch_status, ch_type, chal_validated_at in challenges
        ]

        return {
            'status': authz_status,
            'expires': expires_at,
            'identifier': {'type': 'dns', 'value': domain},
            'challenges': challenges_list,
        }
    else:
        raise ACMEException(status_code=status.HTTP_404_NOT_FOUND, exctype='malformed', detail='specified authorization not found for current account', new_nonce=data.new_nonce)


@api.post('/new-authz')
async def new_pre_authz(data: Annotated[RequestData, Depends(SignedRequest())]):
    raise ACMEException(status_code=status.HTTP_403_FORBIDDEN, exctype='unauthorized', detail='pre authorization is not supported', new_nonce=data.new_nonce)
