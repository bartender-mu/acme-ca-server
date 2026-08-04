from fastapi import Request
from fastapi.responses import RedirectResponse
from starlette.middleware.base import BaseHTTPMiddleware

from . import service

PUBLIC_PATHS = frozenset(
    [
        '/auth/login',
        '/auth/logout',
        '/acme/',
        '/admin/',
        '/directory',
        '/endpoints',
        '/openapi.json',
        '/favicon.png',
        '/admin.js',
        '/issue.js',
        '/libs/',
    ]
)


class SessionMiddleware(BaseHTTPMiddleware):  # pylint: disable=R0903
    def __init__(self, app, exclude_patterns: list[str] | None = None):
        super().__init__(app)
        self.exclude_patterns = exclude_patterns or []

    def _is_public(self, path: str) -> bool:
        if path.startswith('/.well-known/acme-challenge/'):
            return True
        for pattern in self.exclude_patterns:
            if path.startswith(pattern):
                return True
        for public in PUBLIC_PATHS:
            if path == public or (public.endswith('/') and path.startswith(public)):
                return True
        return False

    async def dispatch(self, request: Request, call_next):
        path = request.url.path

        if self._is_public(path):
            return await call_next(request)

        cookie = request.cookies.get('session')
        user = service.verify_session_cookie(cookie)

        if not user:
            return RedirectResponse(url='/auth/login', status_code=303)

        request.state.user = user

        response = await call_next(request)

        if cookie and user is None:
            response.delete_cookie('session', path='/')

        return response
