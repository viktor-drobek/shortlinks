# Deployment

This guide describes a local deployment shape. It does **not** mean that an
instance is deployed or publicly available.

## Prerequisites

- Docker Engine with Compose.
- A reverse proxy that terminates HTTPS and provides OIDC authentication.
- A durable private directory for the database and two separate key files.

The app requires a 32-byte AES key encoded as hexadecimal in
`SHORTLINKS_KEY_FILE`. `SHORTLINKS_PROXY_KEY_FILE` holds a distinct random
proxy assertion key. Both files must be regular files with owner-only access.
They are mounted read-only and never copied into the image.

## Start the container

Set these values in the shell or an untracked environment file:

```sh
export SHORTLINKS_BASE_URL='https://s.2050.su'
export SHORTLINKS_DATA_DIR="$PWD/data"
export SHORTLINKS_ENCRYPTION_KEY_FILE="$PWD/secrets/encryption.key"
export SHORTLINKS_PROXY_KEY_FILE="$PWD/secrets/proxy.key"
install -d -m 0700 "$PWD/secrets"
# Create keys only for a new installation. Never overwrite existing keys.
(umask 077; set -C; openssl rand -hex 32 > "$SHORTLINKS_ENCRYPTION_KEY_FILE")
(umask 077; set -C; openssl rand -hex 32 > "$SHORTLINKS_PROXY_KEY_FILE")
sudo install -d -m 0700 -o 65532 -g 65532 "$SHORTLINKS_DATA_DIR"
sudo chown 65532:65532 "$SHORTLINKS_ENCRYPTION_KEY_FILE" "$SHORTLINKS_PROXY_KEY_FILE"
sudo chmod 0600 "$SHORTLINKS_ENCRYPTION_KEY_FILE" "$SHORTLINKS_PROXY_KEY_FILE"
docker compose config --quiet
docker compose up --build -d
```

`compose.yaml` makes the root filesystem read-only, runs as UID/GID 65532,
drops Linux capabilities, provides `/data` as the only persistent writable
location, and binds the service to loopback. For a bind-mounted `/data`, ensure
it is owned by the container identity before startup.

The process configuration uses the `SHORTLINKS_*` names shown in
`compose.yaml`: `SHORTLINKS_LISTEN`, `SHORTLINKS_BASE_URL`,
`SHORTLINKS_ORIGIN`, `SHORTLINKS_DB`, `SHORTLINKS_KEY_FILE`, and
`SHORTLINKS_PROXY_KEY_FILE`. Key-file paths are required in production; the
public base URL and Origin must be the same HTTPS origin.

## Reverse proxy contract

The proxy alone implements sign-in. It must:

1. allow anonymous `GET` and `HEAD` only for `/<code>`;
2. require OIDC authentication and the `/links` group for `/manage` and
   `/api/v1/*`;
3. strip inbound `X-Shortlinks-Proxy-Key`, `X-Auth-Request-User`, and
   `X-Real-IP`, then set the assertion key, authenticated user, and client IP
   itself;
4. pass the exact public HTTPS origin as the application origin configuration;
5. keep the backend private; do not publish its listener directly.

The public API has no CORS policy. Browser management submissions require the
same configured Origin and a user-bound CSRF value. Machine clients use the
public HTTPS API through the proxy with a bearer token authorized for `/links`;
they must also send `X-Shortlinks-Client: api`. The proxy assertion key never
leaves the proxy-to-app hop.

## Health and backup

`GET /healthz` is a liveness endpoint and deliberately discloses neither
secret nor database status. Monitor it through the private listener or a
separately protected proxy route.

Back up the SQLite database with access controls equivalent to the encryption
key. SQLite uses adjacent WAL files while active, so use a SQLite-consistent
backup procedure or stop the service before copying files. Test restores in an
isolated environment with the corresponding encryption key.

## Upgrade and rollback

1. Build the candidate image and run `docker compose config`.
2. Run the CI checks before promotion.
3. Back up the database consistently.
4. Replace the image and restart only the local service.
5. Verify `/healthz`, a protected management request, and a test redirect.

Never rotate or replace encryption keys without an explicit migration plan:
existing destinations cannot be decrypted with a different key.
