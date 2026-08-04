import base64
import hashlib
import hmac
import json
import time
from dataclasses import dataclass
from typing import Literal

import bcrypt
from config import settings

import db


@dataclass
class SessionUser:
    user_id: str
    username: str
    group_name: Literal['admin', 'readonly']


def hash_password(password: str) -> str:
    return bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()


def verify_password(password: str, password_bcrypt: str) -> bool:
    return bcrypt.checkpw(password.encode(), password_bcrypt.encode())


def _get_session_secret() -> bytes:
    secret = settings.admin_web.session_secret
    if not secret:
        raise RuntimeError('admin_web.session_secret is not configured')
    return secret.get_secret_value().encode()


def make_session_cookie(user: SessionUser) -> str:
    payload = {
        'uid': user.user_id,
        'usr': user.username,
        'grp': user.group_name,
        'exp': int(time.time()) + int(settings.admin_web.session_max_age.total_seconds()),
    }
    json_bytes = json.dumps(payload, separators=(',', ':')).encode()
    encoded = base64.urlsafe_b64encode(json_bytes).rstrip(b'=')
    sig = hmac.new(_get_session_secret(), encoded, hashlib.sha256).hexdigest()
    return f'{encoded.decode()}.{sig}'


def verify_session_cookie(cookie_value: str | None) -> SessionUser | None:
    if not cookie_value:
        return None
    try:
        encoded_b64, sig = cookie_value.split('.', 1)
        encoded = encoded_b64.encode()
        expected_sig = hmac.new(_get_session_secret(), encoded, hashlib.sha256).hexdigest()
        if not hmac.compare_digest(sig, expected_sig):
            return None
        payload = json.loads(base64.urlsafe_b64decode(encoded + b'=='))
        if payload['exp'] < time.time():
            return None
        return SessionUser(user_id=payload['uid'], username=payload['usr'], group_name=payload['grp'])
    except (ValueError, KeyError, json.JSONDecodeError, TypeError):
        return None


async def get_user(username: str):
    async with db.transaction(readonly=True) as sql:
        record = await sql.record(
            """select id, username, password_bcrypt, group_name from web_users where username = $1""",
            username,
        )
    return record


async def get_user_by_id(user_id: str):
    async with db.transaction(readonly=True) as sql:
        record = await sql.record(
            """select id, username, group_name from web_users where id = $1""",
            user_id,
        )
    return record


async def create_user(user_id: str, username: str, password_bcrypt: str, group_name: Literal['admin', 'readonly']):
    async with db.transaction() as sql:
        await sql.exec(
            """insert into web_users (id, username, password_bcrypt, group_name) values ($1, $2, $3, $4) on conflict do nothing""",
            user_id,
            username,
            password_bcrypt,
            group_name,
        )
