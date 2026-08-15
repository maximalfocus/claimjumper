# claimjumper

`claimjumper` is a **FICTIONAL LOCAL DEMO** of JSON Web Token (JWT) verification for the Northstar
Parcel Exchange. It places a secure verifier beside an explicitly gated vulnerable variant that
demonstrates exactly three flaws:

1. trusting an unsigned `alg:none` token;
2. accepting a correctly signed but expired token; and
3. verifying HS256 with a human-memorable secret that a fixed, bounded recovery exercise recovers
   from a tiny built-in candidate list.

All three reach the same protected operation — releasing held parcel `NPE-204` — while the secure
application rejects them uniformly and preserves the parcel state. A correctly signed, unexpired
dispatcher token succeeds in both applications, proving that the fix preserves legitimate use. The
demonstration is fully simulated and local: it ships no general-purpose token forger or key-recovery
tool, contacts no real system, and confines every state change to a disposable in-container database.

The fixture identities are courier `river` and dispatcher `mara`. A dispatcher may release the held
parcel; a courier is authenticated and then denied. All state lives in a disposable SQLite database
inside a hardened container.

## What the verifier proves

A JWT has Base64url-encoded header and claim segments plus a signature. Decoding the first two
segments only reveals caller-written data; it does **not** authenticate that data. This secure API
instead:

1. allows only configured `HS256`, independently of the received `alg` header;
2. verifies the signature with a new process-local key containing at least 256 bits of entropy;
3. requires and validates `iss`, `aud`, `sub`, `role`, `iat`, `nbf`, and `exp` with zero leeway and
   requires `jti` for correlation;
4. matches `sub` and `role` to the server-side fictional user record; and
5. only then applies the shared dispatcher-only authorization rule.

Authentication failures all return the same `401` response and `WWW-Authenticate: Bearer` challenge.
The server emits one correlatable `token_rejected` event with a bounded internal reason, but never
logs the compact token, Authorization header, signature, decoded claims, or key. A valid courier gets
a generic `403`, which demonstrates that authentication and authorization are separate controls.

The vulnerable verifier deliberately makes three different incomplete decisions. For `alg:none`, it
decodes and trusts attacker-written claims without verifying a signature. For HS256 it verifies the
signature, issuer, audience, claim schema, not-before time, and server-side user/role match but omits
the expiration check. And its HS256 signing key is a conspicuously fictional human-memorable secret
that the fixed recovery exercise can guess from a tiny built-in candidate list. All three paths then
use the exact shared dispatcher authorization and parcel transaction code, so the demonstrated
difference is authentication rather than authorization.

## The three vulnerable contrasts

### 1. Unsigned-token path

Starting from a courier token, the demo changes `sub` to `mara`, changes `role` to `dispatcher`,
declares `alg:none`, and omits a signature. The vulnerable API accepts the attacker-written identity
and releases the parcel; the secure API returns the uniform `401`, emits one generic event, and
leaves the fixture state byte-for-byte unchanged.

### 2. Expired-token path

The demo uses a correctly signed dispatcher token whose `exp` is earlier than the verifier's
controlled current time. The vulnerable API accepts it and releases the parcel; the secure API
returns the same uniform `401` and preserves state. Boundary tests cover one instant before `exp`,
exactly at `exp` (rejected by the secure app), and after `exp`.

### 3. Weak-secret path and the bounded recovery exercise

Given one fixed vulnerable-app courier token, the recovery exercise tests a tiny built-in list of
conspicuously fictional candidate strings, recovers the vulnerable app's human-memorable HS256
secret, forges one fixed dispatcher token, and releases the parcel in the vulnerable app.

The exercise is deliberately bounded:

- it accepts **exactly** the checked-in vulnerable courier token and **exactly one** checked-in
  candidate list;
- it tries each entry at most once and prints only the candidate count plus a labeled fictional
  match;
- it refuses altered or external tokens, alternate lists, command-line candidate values, paths,
  URLs, stdin, plugins, and environment overrides **before** any candidate testing;
- it performs no network request and exposes no reusable decoder, signer, forger, cracker, scanner,
  or arbitrary output path;
- it derives exactly one fixed forged dispatcher token for the local vulnerable fixture only and
  clears in-memory candidate/key values when the case completes.

The secure application's signing key is newly generated at process start with at least 256 bits of
entropy and is never printed, returned, persisted, host-mounted, or exposed to the walkthrough. The
same fixed candidate list therefore finds no match for a secure-app courier token, and the attempted
weak-key forgery receives the uniform `401`, one generic redacted event, and byte-for-byte unchanged
state — the strong-key counterproof.

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

## Run the three vulnerable contrasts

The vulnerable API is local-only educational material. Starting it requires two deliberate actions:
the `vulnerable` Compose profile and the exact `ALLOW_VULNERABLE_DEMO=true` environment value. Missing
or misspelled values fail closed. The service binds only to `127.0.0.1:8001`, runs with the same
non-root/read-only hardening, stores only ephemeral state, and uses an isolated internal Docker
network with no external egress.

Each fixed command starts both APIs, resets each app independently, obtains only its process-local
fixture, runs the vulnerable impact and secure rejection, and prints decoded fictional claims,
verdict, HTTP result, and before/after state with compact tokens and signatures redacted:

```sh
ALLOW_VULNERABLE_DEMO=true docker compose --profile vulnerable run --rm --build walkthrough unsigned
ALLOW_VULNERABLE_DEMO=true docker compose --profile vulnerable run --rm --build walkthrough expired
```

The weak-secret recovery case is a separate fixed tool that needs no service. It runs with no
network access, accepts no arguments, environment overrides, or stdin, and prints only the candidate
count and the labeled fictional match:

```sh
docker compose --profile tools run --rm --build recovery
```

Stop and remove the disposable services with:

```sh
docker compose --profile vulnerable down
```

Reset the disposable fixture state at any time:

```sh
docker compose exec secure python -c \
  'import urllib.request; urllib.request.urlopen(urllib.request.Request("http://127.0.0.1:8000/demo/reset", method="POST"))'
```

Remove the service and ephemeral state with `docker compose down`.

## Integrated walkthrough

One command resets and runs, in fixed order, the unsigned impact/secure rejection, the expired
impact/secure rejection, the weak-secret recovery/impact/strong-key counterproof, valid courier
parity, and valid dispatcher parity:

```sh
ALLOW_VULNERABLE_DEMO=true docker compose --profile vulnerable run --rm --build integrated
```

It displays the relevant fictional decoded headers/claims, verifier and authorization verdicts, HTTP
outcomes, audit-event presence, and before/after state while redacting compact tokens, signatures,
keys, and Authorization headers. It finishes with a machine-checkable per-case and overall PASS/FAIL
summary, exits nonzero on any unexpected result, and completes in under five minutes from a warm
image cache.

## Regression matrix

The shared verification boundary proves at minimum:

| Axis | Vulnerable app | Secure app |
|---|---|---|
| unsigned `alg:none` | impact: `200` release | uniform `401`, one event, unchanged state |
| expired (before/at/after `exp`) | accepts on/after `exp` | rejects exactly at and after `exp` |
| weak secret | fixed-list recovery, forgery, impact | no candidate match; forgery → uniform `401`, unchanged state |
| malformed segments | — | uniform `401` |
| unsupported algorithm | — | uniform `401` |
| invalid signature | — | uniform `401` |
| missing required claim | — | uniform `401` |
| wrong issuer / wrong audience | — | uniform `401` |
| not-yet-valid / future-issued | — | uniform `401` |
| unknown subject / inconsistent role | — | uniform `401` |
| valid courier | authenticated then identical `403` | authenticated then identical `403` |
| valid dispatcher | identical `200` + release | identical `200` + release |
| already-released conflict | identical `409` | identical `409` |
| injected pre-commit failure | identical `500` + rollback | identical `500` + rollback |
| containment / startup gates / drift | two opt-ins, no egress, shared routes | default only, hardened |

Logs and walkthrough output contain no full compact token, Authorization header, signature, or key.

## Verify

From a clean checkout, one command runs Ruff formatting/lint, strict mypy, Pytest coverage, the
uniform rejection and redaction matrix, transaction tests, real-loopback HTTP checks, static
container-hardening and startup-gate assertions, the recovery boundary tests, and the integrated
walkthrough with its five-minute bound:

```sh
ALLOW_VULNERABLE_DEMO=true docker compose --profile vulnerable run --rm --build integrated
```

For a fast test-only run, the same suite without the walkthrough is available as:

```sh
docker compose --profile tools run --rm --build verify
```

GitHub Actions invokes the integrated command on every push and pull request. The tests cover the
three attack axes; expiration boundaries; malformed, unsigned, expired, wrongly signed,
wrong-issuer/audience, not-yet-valid, future-issued, missing-claim, unknown-subject, and
inconsistent-role tokens; valid courier and dispatcher behavior; already-released conflict; injected
pre-commit rollback; recovery boundary refusals (altered/external tokens, arguments, environment
overrides, stdin) and at-most-once candidate attempts; the strong-key counterproof; fixture/reset
behavior; and hardened defaults.

This repository is educational and local-only. It is not a complete authentication architecture and
does not cover passwords, OAuth/OIDC, MFA, revocation, browser storage, TLS, deployment, or hosting.
For production systems, use maintained JWT libraries, managed high-entropy secrets, explicit
algorithm allowlists, and complete claim validation. Background standards: [OWASP API2:2023 Broken
Authentication](https://owasp.org/API-Security/editions/2023/en/0xa2-broken-authentication/),
[RFC 7519](https://www.rfc-editor.org/rfc/rfc7519.html), and
[RFC 8725](https://www.rfc-editor.org/rfc/rfc8725.html).
