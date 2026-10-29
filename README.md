# shortlinks

A self-hosted short-link service for the public origin
[`https://s.2050.su`](https://s.2050.su). The management interface and API are
protected at the reverse proxy by OIDC and the `/links` group; public short
links are redirect-only.

> **Current status:** source code and local deployment materials are present.
> No production deployment or public integration is claimed here.

## What it does

- creates opaque, eight-character short codes for HTTP(S) destinations;
- keeps links private to their authenticated owner;
- encrypts destinations at rest in SQLite;
- supports optional UTC expiry, owner-only revocation, and API idempotency;
- checks destinations weekly and removes only after two separated missing
  checks; check state is persisted with the link;
- renders a small responsive Russian management interface without external
  assets.

## Management UI

The screenshots below document the interface from the local application.
They are intentionally free of credentials and real tokens.

![Desktop management interface](docs/screenshots/desktop.png)

![Mobile management interface](docs/screenshots/mobile.png)

## Quick local checks

Requires Go 1.26.10:

```sh
go test -race ./...
go vet ./...
```

Additional security checks used by CI are:

```sh
govulncheck ./...
gosec ./...
gitleaks git --redact --no-banner
```

Build a local container:

```sh
docker build --tag shortlinks:local .
```

For deployment requirements, reverse-proxy behavior, secret handling, and
backups, read [docs/deployment.md](docs/deployment.md). For disclosure and
security boundaries, read [SECURITY.md](SECURITY.md).

## API

The authenticated API is under `/api/v1/links`. It is intentionally accessible
only through the reverse proxy. API clients use their own proxy-issued bearer
token with the `/links` group and send `X-Shortlinks-Client: api`; they never
receive the proxy assertion key.

The [OpenAPI description](docs/openapi.yaml) lists the request and response fields.

| Method | Path | Purpose |
| --- | --- | --- |
| `POST` | `/api/v1/links` | Create a link, optionally with expiry and an idempotency key |
| `GET` | `/api/v1/links` | List the current owner's links |
| `GET` | `/api/v1/links/{id}` | Read one owned link |
| `DELETE` | `/api/v1/links/{id}` | Revoke one owned link |
| `DELETE` | `/api/v1/links` | Revoke by a 64-character hexadecimal idempotency key |
| `GET`, `HEAD` | `/{code}` | Public redirect, no sign-in required |

A machine client sends `Authorization: Bearer <token>` to the reverse proxy,
`X-Shortlinks-Client: api`, and `Content-Type: application/json` for creation.
For example, a creation body is:

```json
{"url":"https://example.org/meeting?jwt=demo#config.callDisplayName=Demo","title":"Meeting"}
```

The response includes `id`, `code`, `short_url`, and `expires_at`. Codes contain
exactly eight case-sensitive characters from `0–9`, `A–Z`, and `a–z`, generated
with cryptographic randomness. The complete destination, including its query
and fragment, is preserved. Do not put real credentials in command history.

## Weekly destination checks

Each link becomes due seven days after creation or its previous completed
check. The worker sends bounded `HEAD` requests to public HTTP(S) endpoints
on ports 80 and 443. DNS answers and every redirect are checked against the
public-address policy before connecting; destination URLs are not logged.

Only HTTP 404 or an interrupted connection (EOF or reset) marks a link as
missing. A second missing result at least seven days later removes the
redirect and clears its encrypted target. A successful 2xx check clears the
mark. Timeouts, DNS/TLS failures, blocked destinations, and other HTTP statuses
are inconclusive and do not trigger deletion. Retired codes are never reused.
Expired links stop redirecting immediately with HTTP 410, independently of the
weekly checker. Deletion does not imply secure erasure from historical backups.

## NEP / Jitsi integration

The NEP issuer can call the API with a dedicated proxy-authorized identity to
wrap the complete guest URL, including its JWT and connection settings. The
service does not parse or issue Jitsi JWTs. NEP passes the guest expiry, so its
24-hour validity remains unchanged. On renewal or call deletion, NEP revokes
the old JWT locally and queues external cleanup by idempotency key. This also
handles a lost create response without needing to recover its remote ID.
Existing participants are not disconnected. If external shortening is
unavailable, NEP can fall back to its local guest route.

## License

[MIT](LICENSE)
