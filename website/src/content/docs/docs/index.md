---
title: Authentication, in your stack
description: Start with easy-auth, a pre-release Rust authentication library and service.
---

easy-auth shares authentication policy and PostgreSQL transactions between an embedded Axum library and a standalone service. Your application owns its authorization rules.

This is **pre-release software**. Start from the repository, check each feature's documented scope, and configure providers deliberately. Availability does not establish independent security approval or general interoperability.

- [Run the local development stack](/docs/getting-started/)
- [Embed the shared router in Axum](/docs/embedding/)
- [Check feature availability and release boundaries](/docs/features/)

## Design boundaries

Users, provider identities, credentials, sessions and application authorization have separate responsibilities. PostgreSQL storage is scoped to a realm; matching email addresses do not automatically link accounts.

Both integration modes use the same core. HTTP adapters contain no persistence policy; database transactions enforce state changes. Consult the [architecture overview](https://github.com/Deuspheara/easy-auth/blob/main/docs/architecture/overview.md) for those boundaries.

## Public reference guides

The Authentication navigation contains selected guides from committed repository sources. The website never imports private review packets, local research, tracker exports or environment files. [Source provenance](/docs-provenance.json) records the exact revision and guide hashes used for this build.
