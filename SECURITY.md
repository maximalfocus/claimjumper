# Security policy

`claimjumper` is a **FICTIONAL LOCAL DEMO**. It is educational material that runs only on a
developer's own machine through Docker Compose. It is not a product, not a service, and not a
reference authentication architecture. Nothing here is hosted, deployed, or offered as a supported
release, and the project contacts no real system.

## The vulnerabilities in this repository are intentional

This repository deliberately ships a vulnerable API variant beside a secure one so that the
difference in JWT verification is observable. The following are **intended, documented behaviour**
and are not accepted as vulnerability reports:

- the vulnerable variant trusting an unsigned `alg:none` token and its attacker-written claims;
- the vulnerable variant accepting a correctly signed dispatcher token at or after its `exp`; and
- the vulnerable variant signing HS256 with a conspicuously fictional, human-memorable secret that
  the bounded recovery exercise recovers from a tiny built-in candidate list.

All keys, secrets, tokens, users, and parcels in this repository are fictional demonstration values
labelled `FICTIONAL LOCAL DEMO`. They authenticate nothing outside this demo and are safe to read.

The vulnerable service is not the default. It starts only with both the `vulnerable` Compose profile
and `ALLOW_VULNERABLE_DEMO=true`, binds only to `127.0.0.1`, has no egress, and keeps all state in a
disposable in-container database.

## Reporting an unintended vulnerability

Please report anything that is *not* on the list above privately, rather than in a public issue —
for example a flaw in the secure verifier that contradicts its documented policy, a containment
escape from the local-only boundary, a real credential committed by mistake, or an input path in the
bounded recovery exercise that accepts external material.

Use either channel:

1. **GitHub private advisories (preferred).** Open the repository's **Security** tab and choose
   *Report a vulnerability*. This creates a private advisory visible only to the maintainer.
2. **Email.** Write to <byzhubaiyuan@gmail.com> if you cannot use the Security tab.

Please include the affected file or command, what you observed, and how to reproduce it locally.

## What to expect

This is a personal educational project maintained on a best-effort basis. There is no service level
agreement, no supported-version matrix, and no security release channel. Confirmed unintended issues
are fixed on the default branch; the intentional flaws above stay exactly as they are, because
demonstrating them is the entire point of the repository.

## Scope boundary

Out of scope by design, and documented as such in the README: hosting, deployment, TLS, passwords,
OAuth/OIDC, MFA, refresh tokens, revocation and logout, browser token storage, and algorithm-confusion
attacks. Absence of those is not a vulnerability in this repository.
