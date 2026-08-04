# Internal ACME CA Server Documentation

## Overview

A self-hosted ACME (Automated Certificate Management Environment) CA server with a web UI for certificate management.

## Architecture

| Component | Description |
|-----------|-------------|
| Web UI | Certificate log viewer, download, and issuance |
| ACME API | RFC 8555 compliant protocol for certificate issuance |
| Admin API | Key download, revocation, and deletion |
| Built-in CA | Internal certificate authority |

## Web UI Authentication

### Credentials

| User | Password Env Var | Group | Permissions |
|------|-----------------|-------|-------------|
| `admin` | `ADMIN_WEB_PASSWORD` | admin | View, download, generate, revoke, delete |
| `readonly` | `ADMIN_WEB_READONLY_PASSWORD` | readonly | View, download |

### Endpoints

| URL | Method | Description | Auth Required |
|-----|--------|-------------|---------------|
| `/` | GET | Index page | Yes |
| `/auth/login` | GET/POST | Login page | No |
| `/auth/logout` | GET | Logout | Yes |
| `/certificates` | GET | Certificate log | Yes |
| `/certificates/{serial}` | GET | Download certificate chain | Yes |
| `/certificates/{serial}/package` | GET | Download cert+key+chain zip | Yes |
| `/domains` | GET | Domain log | Yes |
| `/issue` | GET | Issue certificate page | Admin only |
| `/endpoints` | GET | Swagger UI | No |

### Login

```bash
# Login via web form
curl -c cookies.txt -X POST http://localhost:8080/auth/login \
  -d "username=readonly&password=readonly"

# Access protected page
curl -b cookies.txt http://localhost:8080/certificates
```

## ACME Protocol

### ACME Endpoints

| URL | Description |
|-----|-------------|
| `/acme/directory` | ACME directory |
| `/acme/newNonce` | Get nonce |
| `/acme/newAccount` | Create account |
| `/acme/newOrder` | Create order |
| `/acme/{authz_id}` | Authorization |
| `/acme/{challenge_id}` | Challenge |
| `/acme/{order_id}/cert` | Download certificate |

### Challenge Types

| Type | Enabled By | Description |
|------|-----------|-------------|
| HTTP-01 | `ACME_HTTP01_ENABLED=true` | File-based validation |
| DNS-01 | `ACME_DNS01_ENABLED=true` | DNS TXT record validation |

### Example: Certbot

```bash
# Register account
certbot register \
  --server http://localhost:8080/acme/directory \
  --agree-tos \
  --email admin@example.com

# Issue certificate (HTTP-01)
certbot certonly \
  --server http://localhost:8080/acme/directory \
  -d example.com \
  --http-01-port 80 \
  --http-01-address 0.0.0.0

# Issue certificate (DNS-01)
certbot certonly \
  --server http://localhost:8080/acme/directory \
  -d example.com \
  --dns-provider certbot-dns-cloudflare \
  --dns-cloudflare-credentials ~/.cloudflare.ini
```

### Example: uacme

```bash
# Edit uacme config
# DOMAINS="example.com"
# WELLKNOWN="/var/www/.well-known/acme-challenge"
# CONTACT="admin@example.com"
# ACME_URL="http://localhost:8080/acme/directory"

uacme -v -h http01 issue example.com
```

## Admin API

Requires `X-Admin-API-Key` header with valid `ADMIN_API_KEY`.

### Endpoints

| Method | URL | Description |
|--------|-----|-------------|
| POST | `/admin/issue` | Issue new certificate |
| POST | `/admin/revoke` | Revoke certificate |
| POST | `/admin/delete` | Delete certificate |
| GET | `/admin/download/{serial}` | Download cert+key+chain |

### Issue Certificate

```bash
curl -X POST http://localhost:8080/admin/issue \
  -H "X-Admin-API-Key: $ADMIN_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{"domains": ["example.com"], "key_type": "ec", "key_size": 256}'
```

Response:
```json
{
  "serial_number": "...",
  "certificate": "-----BEGIN CERTIFICATE-----\n...",
  "chain": "-----BEGIN CERTIFICATE-----\n...",
  "private_key": "-----BEGIN PRIVATE KEY-----\n...",
  "not_before": "2026-01-01T00:00:00Z",
  "not_after": "2026-03-02T00:00:00Z"
}
```

### Revoke Certificate

```bash
curl -X POST http://localhost:8080/admin/revoke \
  -H "X-Admin-API-Key: $ADMIN_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{"serial_number": "..."}'
```

### Delete Certificate

```bash
curl -X POST http://localhost:8080/admin/delete \
  -H "X-Admin-API-Key: $ADMIN_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{"serial_number": "..."}'
```

## Configuration

### Environment Variables

#### Web UI

| Variable | Default | Description |
|----------|---------|-------------|
| `WEB_ENABLED` | `True` | Enable web UI |
| `WEB_ENABLE_PUBLIC_LOG` | `False` | Allow unauthenticated cert viewing |
| `WEB_APP_TITLE` | `ACME CA Server` | Web UI title |
| `ADMIN_WEB_PASSWORD` | - | Admin user password |
| `ADMIN_WEB_READONLY_PASSWORD` | - | Readonly user password |
| `ADMIN_WEB_SESSION_SECRET` | - | Session signing secret |

#### ACME

| Variable | Default | Description |
|----------|---------|-------------|
| `ACME_MAIL_REQUIRED` | `True` | Require email in ACME account |
| `ACME_HTTP01_ENABLED` | `True` | Enable HTTP-01 challenge |
| `ACME_DNS01_ENABLED` | `False` | Enable DNS-01 challenge |
| `ACME_DNS01_NAMESERVERS` | - | Comma-separated DNS servers |
| `ACME_DNS01_MAX_RETRIES` | `3` | DNS validation retry count |
| `ACME_DNS01_RETRY_DELAY_SECONDS` | `2` | Delay between retries |

#### CA

| Variable | Default | Description |
|----------|---------|-------------|
| `CA_ENABLED` | `True` | Enable built-in CA |
| `CA_ENCRYPTION_KEY` | - | Fernet key for key encryption |
| `CA_IMPORT_DIR` | `/import` | CA key/cert import directory |

#### Admin API

| Variable | Default | Description |
|----------|---------|-------------|
| `ADMIN_API_KEY` | - | Admin API authentication key |

#### General

| Variable | Default | Description |
|----------|---------|-------------|
| `EXTERNAL_URL` | - | Public URL (no trailing `/`) |
| `DB_DSN` | - | PostgreSQL connection string |
| `LOG_LEVEL` | `info` | Logging level |

### Docker Compose Example

```yaml
app:
  environment:
    EXTERNAL_URL: https://ca.example.com
    DB_DSN: postgresql://postgres:secret@db/postgres
    CA_ENCRYPTION_KEY: <generate-with-openssl-rand-base64-32>
    ADMIN_API_KEY: <generate-random-key>
    ADMIN_WEB_PASSWORD: <admin-password>
    ADMIN_WEB_READONLY_PASSWORD: <readonly-password>
    ADMIN_WEB_SESSION_SECRET: <generate-random-secret>
    WEB_ENABLED: 'True'
    WEB_ENABLE_PUBLIC_LOG: 'True'
    ACME_MAIL_REQUIRED: 'False'
    ACME_HTTP01_ENABLED: 'True'
    ACME_DNS01_ENABLED: 'False'
```

## Certificate Download

### Via Web UI

1. Login at `/auth/login`
2. Navigate to `/certificates`
3. Click **download** button next to certificate

Downloads a zip containing:
- `{domain}.crt` - Certificate
- `{domain}.key` - Private key
- `{domain}.chain.crt` - Certificate chain

### Via ACME

```bash
# Download via certbot
certbot install \
  --cert-path /etc/letsencrypt/live/example.com/fullchain.pem \
  --key-path /etc/letsencrypt/live/example.com/privkey.pem

# Or manually from ACME endpoint
curl -o cert.pem http://localhost:8080/acme/certificate/{order_id}
```

### Via Admin API

```bash
curl -O http://localhost:8080/admin/download/{serial_number} \
  -H "X-Admin-API-Key: $ADMIN_API_KEY"
```

## CRL (Certificate Revocation List)

```bash
# Download CRL
curl http://localhost:8080/ca/crl.pem
```

## Troubleshooting

### Certificate Not Found

If downloading a certificate fails with "unknown certificate":
- Verify the serial number is correct
- Check the certificate exists in the database

### DNS-01 Challenge Fails

1. Verify `ACME_DNS01_ENABLED=true`
2. Check DNS server configuration with `ACME_DNS01_NAMESERVERS`
3. Ensure `_acme-challenge` TXT record can be created

### Login Fails

1. Verify `ADMIN_WEB_PASSWORD` is set
2. Check password matches exactly
3. Ensure session hasn't expired (default 24h)

### Database Migration Issues

If tables don't exist after upgrade:
```bash
# Reset migration level (dangerous - loses data)
docker exec ca-server_db_1 psql -U postgres -c "UPDATE migrations SET migration = 0;"
# Restart app to re-run migrations
```
