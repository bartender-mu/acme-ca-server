# AGENTS.md — acme-ca-server

## Project shape
- Python/FastAPI ACME server with a built-in CA, optional web UI, and Postgres backend.
- Source lives in `app/`. The app is **not** installed as a Python package; imports are absolute from the `app` directory, e.g. `import main`, `import config`, `from db import transaction`.
- `pyproject.toml` and `project.toml` are currently identical copies. They configure the single package, tests, and linting.
- Entry point: `app/main.py:app`. Docker and dev run it as `uvicorn main:app` from inside `/app`.

## Running the app locally
- Dev stack: `docker compose -f compose.dev.yml up --build`. It builds the image, starts Postgres, generates a CA in `import/`, and mounts `app/` and `import/` read-only with Uvicorn `--reload`.
- To run Uvicorn from the repo root without Docker: `PYTHONPATH=app uvicorn main:app --host 0.0.0.0 --port 8080 --reload`.
- The `import/` directory is gitignored. On first startup it must contain `ca.pem` and `ca.key`; the dev compose generates them. After import, the CA data lives in the database and the key files can be removed.
- If `CA_ENCRYPTION_KEY` is missing, the app logs a freshly generated key and exits. Use that value, or set it explicitly before startup.
- Configuration uses pydantic-settings with env prefixes `acme_*`, `ca_*`, `mail_*`, `web_*` plus top-level `EXTERNAL_URL`, `DB_DSN`, `LOG_LEVEL`. Env var names are case-insensitive, so `CA_ENCRYPTION_KEY` and `ca_encryption_key` both work.

## Architecture
- `app/main.py`: assembles the FastAPI app, sets lifespan (DB connect → migrations → CA init → cronjobs), and ACME-specific exception handling.
- `app/acme/`: ACME protocol endpoints (accounts, orders, authorizations, challenges, certificates, nonces, directory).
- `app/ca/`: internal CA, CRL endpoint, and CA import logic. Disable with `CA_ENABLED=False` to plug in a custom backend by replacing `/app/ca/service.py`.
- `app/db/`: asyncpg pool + transaction helper. `app/db/migrations/` are numbered `###.sql` files run in order at startup.
- `app/web/`: web UI and public log; templates are in `app/web/templates/`. Optional static files are served from `/app/web/www/` if present.
- `app/mail/`: SMTP notifications and templates.
- The version string in `app/main.py` (`'0.0.0'`) is replaced by CI on release; do not change it manually.

## Testing
- Pytest is configured in the toml files: `pythonpath = "app"`, `testpaths = "tests/pytest/"`, `--import-mode=importlib`.
- Docker tests: `cd tests/pytest && ./run.sh` builds a runner image, starts a Postgres container, and writes HTML coverage to `tests/pytest/coverage/`.
- Local tests: needs a fresh Postgres and `openssl`.
  - Install deps: `pip install -r requirements.txt` and `pip install pytest coverage`.
  - Run: `db_dsn=postgresql://postgres:postgres@localhost/postgres pytest .` (from repo root).
  - Run a single test: `db_dsn=... pytest tests/pytest/test_acme_account.py`.
- `tests/pytest/conftest.py` sets `ca_encryption_key`, `external_url`, `acme_mail_required`, `WEB_ENABLE_PUBLIC_LOG`, creates a temporary CA under `tests/pytest/import-ca/`, and disables background cronjobs so the test run exits cleanly.
- End-to-end tests: `cd tests/e2e && ./run.sh` (CI uses `sudo`). They exercise the real Docker image with certbot, Caddy, uacme, and acme.sh.

## Lint / format / typecheck
The CI `lint.yml` runs these exact commands in order:

```bash
python -m flake8 --max-line-length 179 --ignore=F722,B008,I001,I004,I005 app
pylint app
ruff check app
ruff format --check app
mypy app
```

- Line length is 179 for flake8, pylint, and ruff.
- `ruff format` uses single quotes (`quote-style = "single"`).
- `mypy` disables `import-untyped`.
- Auto-fix: `ruff check --fix app`; auto-format: `ruff format app`.

## Git hooks
- A pre-commit hook is tracked in `.githooks/pre-commit` and runs the same `flake8`, `pylint`, `ruff check`, `ruff format --check`, and `mypy` checks as CI.
- Register it with: `git config core.hooksPath .githooks`.
- The hook runs only when `app/`, `pyproject.toml`, `project.toml`, or `requirements.txt` are staged.
- It requires the same lint tools as CI. If they are missing, the hook aborts with the install command.
- To bypass the hook for a single commit, use `git commit --no-verify`.

## Conventions and gotchas
- Do not add `app.` to imports (e.g., `from app.db import ...`). Use top-level module names because the source directory is on `PYTHONPATH`.
- Add new DB migrations as the next sequential `###.sql` file in `app/db/migrations/`. The app applies them automatically at startup.
- The `SecurityHeadersMiddleware` in `app/web/middleware.py` applies different CSP rules for `/acme/`, `/endpoints`, and `/`. Review it when adding new routes or static mounts.
- `External_url` must not end in `/` in the config; the app appends one automatically.
- The duplicate `pyproject.toml`/`project.toml` should be kept in sync when changing tool config.

## DNS-01 challenge support
- Enable with `ACME_DNS01_ENABLED=True`. HTTP-01 can be kept (`ACME_HTTP01_ENABLED=True`) or disabled.
- The server provisions the `_acme-challenge.<domain>` TXT record via the replaceable hook in `app/acme/challenge/dns_provider.py` (same pattern as the custom CA hook).
- Configure DNS resolvers for validation with `ACME_DNS01_NAMESERVERS` (comma-separated IPs); retry behaviour is configurable via `ACME_DNS01_MAX_RETRIES` and `ACME_DNS01_RETRY_DELAY_SECONDS`.

## Admin endpoint for database certificates
- Enabled only when `ADMIN_API_KEY` is set.
- `POST /admin/issue` returns a freshly generated private key + signed certificate for the requested domains.
  - Request fields: `domains`, `key_type` (`rsa`/`ec`), `key_size` (RSA: `2048`/`4096`; EC: `256`/`384`).
  - Pass the key in the `X-Admin-API-Key` header.
- `POST /admin/revoke` revokes an admin-issued certificate by serial number.
- Admin-issued certificates are stored in the existing `certificates` table (synthetic order/authorization rows) so they appear in the web log and CRL.
