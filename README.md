# claimjumper

`claimjumper` is a **FICTIONAL LOCAL DEMO** of secure JSON Web Token (JWT) verification for the
Northstar Parcel Exchange. This first delivery slice contains only the secure verifier and shared
parcel/authorization boundary. It does not contain an intentionally vulnerable service, token
forger, key-recovery tool, real target, or production identity system.

The fixture identities are courier `river`, dispatcher `mara`, and parcel `NPE-204`. A dispatcher may
release the held parcel; a courier is authenticated and then denied. All state lives in a disposable
SQLite database inside a hardened container.

## What the verifier proves

A JWT has Base64url-encoded header and claim segments plus a signature. Decoding the first two
segments only reveals caller-written data; it does **not** authenticate that data. This secure API
instead:

1. allows only configured `HS256`, independently of the received `alg` header;
2. verifies the signature with a new process-local key containing at least 256 bits of entropy;
3. requires and validates `iss`, `aud`, `sub`, `role`, `iat`, `nbf`, `exp`, and `jti` with zero leeway;
4. matches `sub` and `role` to the server-side fictional user record; and
5. only then applies the shared dispatcher-only authorization rule.

Authentication failures all return the same `401` response and Bearer challenge. The server emits
one correlatable `token_rejected` event with a bounded internal reason, but never logs the compact
token, Authorization header, signature, decoded claims, or key. A valid courier gets a generic `403`,
which demonstrates that authentication and authorization are separate controls.

## Run locally

Docker with Compose is the only host prerequisite. Start the secure service:

```sh
docker compose up --build secure
```

It is reachable only at `http://127.0.0.1:8000`. The container is non-root, capability-free,
`no-new-privileges`, read-only except for ephemeral `/data` and `/tmp` mounts, and attached to an
internal Docker network. The controlled demo clock is configured in `compose.yaml`; application code
uses an injected clock and does not monkey-patch global time.

In another terminal, run one fixed case. Output labels every value fictional, shows decoded header
and claims plus policy/verdict/HTTP/state, and redacts the compact token and signature:

```sh
docker compose exec secure python scripts/manual_case.py courier
docker compose exec secure python scripts/manual_case.py dispatcher
docker compose exec secure python scripts/manual_case.py expired_dispatcher
docker compose exec secure python scripts/manual_case.py unsigned_dispatcher
```

Reset the disposable fixture state at any time:

```sh
docker compose exec secure python -c \
  'import urllib.request; urllib.request.urlopen(urllib.request.Request("http://127.0.0.1:8000/demo/reset", method="POST"))'
```

Remove the service and ephemeral state with `docker compose down`.

## Verify

From a clean checkout, one command runs Ruff formatting/lint, strict mypy, Pytest coverage, the
uniform rejection and redaction matrix, transaction tests, real-loopback HTTP checks, and static
container-hardening assertions:

```sh
docker compose run --rm verify
```

GitHub Actions invokes this same command. The tests cover malformed, unsigned, expired, wrongly
signed, wrong-issuer/audience, not-yet-valid, future-issued, missing-claim, unknown-subject, and
inconsistent-role tokens; valid courier and dispatcher behavior; already-released conflict; injected
pre-commit rollback; exact expiration boundaries; fixture/reset behavior; and hardened defaults.

This repository is educational and local-only. It is not a complete authentication architecture and
does not cover passwords, OAuth/OIDC, MFA, revocation, browser storage, TLS, deployment, or hosting.
For production systems, use maintained JWT libraries, managed high-entropy secrets, explicit
algorithm allowlists, and complete claim validation. Background standards: [OWASP API2:2023 Broken
Authentication](https://owasp.org/API-Security/editions/2023/en/0xa2-broken-authentication/),
[RFC 7519](https://www.rfc-editor.org/rfc/rfc7519.html), and
[RFC 8725](https://www.rfc-editor.org/rfc/rfc8725.html).
