__version__ = '0.0.0'  # replaced during build, do not change

from contextlib import asynccontextmanager
from pathlib import Path

import acme
import auth
import auth.service as auth_service
import ca
import db.migrations  # pylint: disable=wrong-import-order
import web  # pylint: disable=wrong-import-order
from acme.exceptions import ACMEException
from config import settings
from fastapi import FastAPI, HTTPException, Request, status
from fastapi.encoders import jsonable_encoder
from fastapi.exception_handlers import http_exception_handler
from fastapi.exceptions import RequestValidationError
from fastapi.openapi.docs import get_swagger_ui_html
from fastapi.responses import JSONResponse
from fastapi.staticfiles import StaticFiles
from logger import logger  # pylint: disable=wrong-import-order,ungrouped-imports
from pydantic import ValidationError

import db  # pylint: disable=wrong-import-order,ungrouped-imports


async def seed_web_users():
    if settings.admin_web.password:
        password = settings.admin_web.password.get_secret_value()
        password_hash = auth_service.hash_password(password)
        await auth_service.create_user('admin', 'admin', password_hash, 'admin')
        logger.info('web admin user created (login: admin)')

    if settings.admin_web.readonly_password:
        password = settings.admin_web.readonly_password.get_secret_value()
        password_hash = auth_service.hash_password(password)
        await auth_service.create_user('readonly', 'readonly', password_hash, 'readonly')
        logger.info('web readonly user created (login: readonly)')


async def _handle_acme_exception(_request: Request, exc: Exception) -> JSONResponse:
    if isinstance(exc, ACMEException):
        return await exc.as_response()
    if isinstance(exc, ValidationError):
        return await ACMEException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            exctype='malformed',
            detail=exc.json(),
        ).as_response()
    if isinstance(exc, HTTPException):
        return await ACMEException(
            status_code=exc.status_code,
            exctype='serverInternal',
            detail=str(exc.detail),
        ).as_response()
    return await ACMEException(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        exctype='serverInternal',
        detail=str(exc),
    ).as_response()


@asynccontextmanager
async def lifespan(_: FastAPI):
    await db.connect()
    await db.migrations.run()
    await ca.init()
    if settings.admin.api_key:
        import admin as admin_module  # pylint: disable=import-outside-toplevel,redefined-outer-name

        await admin_module.init()
    await seed_web_users()
    await acme.start_cronjobs()
    yield
    await db.disconnect()


app = FastAPI(
    lifespan=lifespan,
    version=__version__,
    redoc_url=None,
    docs_url=None,
    title=settings.web.app_title,
    description=settings.web.app_description,
)
app.add_middleware(
    web.middleware.SecurityHeadersMiddleware,  # type: ignore[arg-type]
    content_security_policy={
        '/acme/': "base-uri 'self'; default-src 'none';",
        '/endpoints': "base-uri 'self'; default-src 'self'; style-src 'self' 'unsafe-inline'; script-src 'self' 'unsafe-inline'; frame-src 'none'; img-src 'self' data:;",
        '/': "base-uri 'self'; default-src 'self'; style-src 'self' 'unsafe-inline'; script-src 'self'; frame-src 'none'; img-src 'self' data:;",
    },
)

if settings.web.enabled:
    app.add_middleware(auth.middleware.SessionMiddleware)

    @app.get('/endpoints', tags=['web'])
    async def swagger_ui_html():
        return get_swagger_ui_html(
            openapi_url='/openapi.json',
            title=app.title,
            swagger_favicon_url='favicon.png',
            swagger_css_url='libs/swagger-ui.css',
            swagger_js_url='libs/swagger-ui-bundle.js',
        )


@app.exception_handler(RequestValidationError)
@app.exception_handler(HTTPException)
@app.exception_handler(ACMEException)
@app.exception_handler(Exception)
async def acme_exception_handler(request: Request, exc: Exception):
    if request.url.path.startswith('/acme/') or isinstance(exc, ACMEException):
        return await _handle_acme_exception(request, exc)
    if isinstance(exc, HTTPException):
        return await http_exception_handler(request, exc)
    if isinstance(exc, (RequestValidationError, ValidationError)):
        return await http_exception_handler(
            request,
            HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=jsonable_encoder(exc.errors())),
        )
    return JSONResponse({'detail': str(exc)}, status_code=status.HTTP_500_INTERNAL_SERVER_ERROR)


app.include_router(acme.router)
app.include_router(acme.directory_router.api)  # serve acme directory under /acme/directory and /directory
app.include_router(ca.router)
app.include_router(auth.router)

if settings.admin.api_key:
    import admin as admin_module

    app.include_router(admin_module.router)

if settings.web.enabled:
    app.include_router(web.router)

    if Path('/app/web/www').exists():
        app.mount('/', StaticFiles(directory='/app/web/www'), name='static')
