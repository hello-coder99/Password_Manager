# AegisVault Deployment Guide (Local Docker & Ubuntu VPS)

> **Critical Security Notice:** Local HTTP (`http://localhost:8080`) is strictly for local development over the loopback interface. **Never transmit account passwords or access AegisVault over HTTP on an untrusted network.** Production deployments must enforce HTTPS (TLS 1.2/1.3) with `SESSION_COOKIE_SECURE=true`.

---

## 1. Local Development with Docker Compose

### 1.1 Generate `.env` from `.env.example`

```bash
cp .env.example .env
```

Generate cryptographically random secrets for `.env`:

```bash
python3 -c 'import secrets; print("SECRET_KEY=" + secrets.token_hex(32))'
python3 -c 'import secrets; print("MYSQL_ROOT_PASSWORD=" + secrets.token_urlsafe(32))'
python3 -c 'import secrets; print("MYSQL_PASSWORD=" + secrets.token_urlsafe(32))'
python3 -c 'import secrets; print("REDIS_PASSWORD=" + secrets.token_urlsafe(32))'
```

Update `.env` with those generated values. For local loopback testing without TLS, keep `SESSION_COOKIE_SECURE=false` and `FLASK_ENV=production`.

### 1.2 Build and Start All Containers

```bash
docker compose up --build -d
```

Verify container health:

```bash
docker compose ps
curl -fsS http://127.0.0.1:8080/api/health
```

Open `http://localhost:8080` in your browser.

---

## 2. Production Deployment on an Ubuntu VPS (HTTPS)

### 2.1 Host Preparation & Firewall (UFW)

On a clean Ubuntu 24.04 LTS VPS:

```bash
sudo apt-get update && sudo apt-get upgrade -y
sudo apt-get install -y ca-certificates curl gnupg ufw certbot

# Configure UFW to allow only SSH and HTTPS/HTTP
sudo ufw default deny incoming
sudo ufw default allow outgoing
sudo ufw allow OpenSSH
sudo ufw allow 80/tcp
sudo ufw allow 443/tcp
sudo ufw enable
```

### 2.2 Provision TLS Certificates with Let's Encrypt

Point your DNS `A` / `AAAA` record (e.g., `vault.example.com`) to your VPS IP address, then obtain a certificate:

```bash
sudo certbot certonly --standalone -d vault.example.com --agree-tos -m security@example.com
```

Certificates will be stored in `/etc/letsencrypt/live/vault.example.com/`.

### 2.3 Production `.env` Configuration

On the VPS, create `.env` with `chmod 600 .env`:

```ini
FLASK_ENV=production
SECRET_KEY=<64-char-random-hex>
MYSQL_ROOT_PASSWORD=<strong-random-root-password>
MYSQL_DATABASE=aegisvault
MYSQL_USER=aegisvault_app
MYSQL_PASSWORD=<strong-random-app-password>
REDIS_PASSWORD=<strong-random-redis-password>
SESSION_COOKIE_SECURE=true
SESSION_COOKIE_SAMESITE=Lax
SESSION_LIFETIME_MINUTES=30
TRUSTED_PROXY_COUNT=1
MAX_CONTENT_LENGTH=524288
```

> Note: `validate_production_config()` in `app/config.py` validates at startup that `SECRET_KEY`, `DATABASE_URL`, and `REDIS_URL` are non-default and refuses to start Gunicorn if any placeholder value remains.

### 2.4 Production HTTPS Nginx Configuration

For TLS termination inside the `nginx` container, mount `/etc/letsencrypt:/etc/letsencrypt:ro` in `docker-compose.yml` and configure the TLS server block in `nginx/nginx.conf`:

```nginx
server {
    listen 8080;
    server_name vault.example.com;
    return 301 https://$host$request_uri;
}

server {
    listen 8443 ssl;
    http2 on;
    server_name vault.example.com;

    ssl_certificate     /etc/letsencrypt/live/vault.example.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/vault.example.com/privkey.pem;
    ssl_protocols       TLSv1.2 TLSv1.3;
    ssl_prefer_server_ciphers on;
    ssl_session_cache   shared:SSL:10m;
    ssl_session_timeout 1d;
    ssl_session_tickets off;

    add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;
    add_header Content-Security-Policy "default-src 'self'; script-src 'self' 'wasm-unsafe-eval'; style-src 'self' https://fonts.googleapis.com; font-src 'self' https://fonts.gstatic.com; img-src 'self' data:; connect-src 'self'; object-src 'none'; base-uri 'self'; form-action 'self'; frame-ancestors 'none';" always;
    add_header X-Content-Type-Options "nosniff" always;
    add_header Referrer-Policy "strict-origin-when-cross-origin" always;
    add_header X-Frame-Options "DENY" always;

    root /usr/share/nginx/html;
    index index.html;

    location /api/ {
        proxy_pass http://flask_backend;
        proxy_http_version 1.1;
        proxy_set_header Connection "";
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $remote_addr;
        proxy_set_header X-Forwarded-Proto https;
        proxy_set_header X-Forwarded-Host $host;
    }

    location / {
        try_files $uri $uri/ /index.html;
    }
}
```

---

## 3. Troubleshooting

- **`RuntimeError: Production startup aborted: SECRET_KEY...`**: Ensure `.env` has a 32+ character random `SECRET_KEY` and no `replace-with-` placeholder strings.
- **`400 CSRF_ERROR` on login/registration behind HTTPS proxy**: Verify `SESSION_COOKIE_SECURE=true` matches `X-Forwarded-Proto https` in `nginx.conf`. If accessing over plain HTTP on localhost, set `SESSION_COOKIE_SECURE=false`.
- **`503 REDIS_UNAVAILABLE`**: Check `docker compose logs redis` and ensure `REDIS_PASSWORD` matches across `redis` and `api` services.
