---
title: Deployment checklist
description: Separate local development from deliberate HTTPS, database, SMTP and provider configuration.
---

GitHub Pages hosts **this documentation only**. It cannot run the Rust authentication server, PostgreSQL or SMTP. Deploy the auth service on infrastructure that runs Rust processes and provides private database connectivity.

## Establish the base service

| Requirement | What to configure                                                  |
| ----------- | ------------------------------------------------------------------ |
| Transport   | HTTPS at a trusted reverse proxy; exact `AUTH_PUBLIC_URL`          |
| Runtime     | `AUTH_DEVELOPMENT=false`; intended loopback/private listener       |
| Database    | Private PostgreSQL access, backups and a tested restore procedure  |
| Email       | TLS SMTP relay and protected credentials                           |
| Browser app | Same configured origin; no invented cookie-sharing scheme          |
| Operations  | Proxy limits, cleanup/retention, monitoring and revocation runbook |

The development `.env.example` is a local tutorial configuration, not a production template. Do not expose its database, Mailpit or plaintext SMTP settings publicly.

## Decide which methods to enable

Start with the base service and activate only the methods your application needs. Missing or partial provider settings must remain errors; do not patch around startup validation.

- **Passwords:** provide and maintain an appropriate production blocklist. Read [password policy](/docs/guides/passwords/).
- **OIDC:** use `oidc-web`, a registered provider client, exact HTTPS issuer/callback, allowed egress origins and explicit algorithm/client authentication settings. Read [OIDC](/docs/guides/oidc/).
- **SAML:** use `saml-web`, `AUTH_SAML_ENABLED=true`, complete HTTPS settings, exact enabled persisted registration/JIT policy and active operator-approved certificate pins. Read [SAML](/docs/guides/saml/) and [SAML release configuration](/docs/guides/saml-release/).
- **Passkeys and provider components:** retain their [documented experimental scope](/docs/features/).

SAML activation follows an explicit maintainer waiver. Independent security review was not performed or passed. The waiver changes no signature, trust, parser, identity, time, correlation, replay or realm checks. Real deployment inputs and interoperability with your IdP still require deployment-specific verification.

## Check the running deployment

Check liveness at `/healthz` and database readiness at `/readyz`. Readiness is not an IdP health check or evidence of a complete protocol login. Exercise your configured sign-in path, session lookup and revocation with the documented normal scenarios.

Keep raw auth material out of logs and metrics. Treat sensitive operations as application transactions with explicit authorization, not simply a successful frontend sign-in screen.

The repository's [deployment architecture](https://github.com/Deuspheara/easy-auth/blob/main/docs/architecture/deployment.md) records additional operational release requirements. Use it as the detailed reference rather than inferring production readiness from a successful build.
