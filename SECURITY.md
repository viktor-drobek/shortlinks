# Security policy

## Reporting a vulnerability

Do not open a public issue for a suspected vulnerability and do not include
credentials, destination URLs, proxy assertions, database files, or request
captures in a report. Use the repository owner's private contact channel from
the GitHub profile. Include a minimal reproduction, affected revision, impact,
and steps to verify the fix.

Reports are acknowledged after review. Fix timing depends on severity and on
whether a safe mitigation is available.

## Security boundary

The public redirect endpoint is intentionally anonymous. Management and API
endpoints are protected by the reverse proxy's OIDC policy and require the
`/links` group. The application is intended to be reachable only from that
proxy.

The proxy must remove client-supplied `X-Shortlinks-Proxy-Key` and
`X-Auth-Request-User`, then add its own values. The proxy assertion key is
private transport material: it is not an API token and must never be exposed
to browser clients or machine clients.

API clients authenticate at the reverse proxy with their own bearer token.
A machine account authorized for `/links` may use the API, but receives no
proxy assertion key.

## Operational requirements

- Store the encryption key and proxy assertion key in separate, regular files
  readable only by the service identity; do not bake them into an image.
- Keep the database directory private and writable only by the service.
- Terminate TLS at the reverse proxy and expose the backend only on a private
  listener or network.
- Preserve the request-size, origin, CSRF, and trusted-proxy controls in the
  application. Do not add CORS for the API.
- Apply updates promptly. The CI workflow runs race tests, static analysis,
  vulnerability checks, and secret scanning on repository code.

Target URLs are encrypted at rest. This does not make the SQLite database or
its backups safe to publish: access to both database and encryption key must
remain restricted.
