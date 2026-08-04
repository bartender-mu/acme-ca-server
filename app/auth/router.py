from pathlib import Path
from typing import Annotated

from fastapi import APIRouter, Form, Query, Response
from fastapi.responses import HTMLResponse, RedirectResponse
from jinja2 import Environment, FileSystemLoader
from pydantic import BaseModel

from . import service

api = APIRouter(prefix='/auth', tags=['auth'])


class LoginResponse(BaseModel):
    model_config = {'extra': 'ignore'}
    success: bool
    error: str | None = None
    group: str | None = None
    username: str | None = None


@api.get('/login', response_class=HTMLResponse)
async def login_page(next_url: Annotated[str | None, Query()] = None):
    engine = Environment(loader=FileSystemLoader(Path(__file__).parent.parent / 'web' / 'templates'), autoescape=True)
    return engine.get_template('login.html').render(next=next_url or '')


@api.post('/login')  # noqa: W0622
async def login(
    response: Response,
    username: Annotated[str, Form()],
    password: Annotated[str, Form()],
    next_url: Annotated[str | None, Query()] = None,  # noqa: W0622
):
    record = await service.get_user(username)
    if not record:
        return LoginResponse(success=False, error='Invalid username or password')

    if not service.verify_password(password, record['password_bcrypt']):
        return LoginResponse(success=False, error='Invalid username or password')

    user = service.SessionUser(
        user_id=record['id'],
        username=record['username'],
        group_name=record['group_name'],
    )
    cookie = service.make_session_cookie(user)
    redirect_url = next_url if next_url and next_url.startswith('/') else '/'

    response = RedirectResponse(url=redirect_url, status_code=303)
    response.set_cookie(
        'session',
        cookie,
        httponly=True,
        samesite='lax',
        secure=False,
        path='/',
    )
    return response


@api.get('/logout')
async def logout(response: Response):
    response = RedirectResponse(url='/auth/login', status_code=303)
    response.delete_cookie('session', path='/')
    return response
