---
title: Users, realms and sessions
description: Understand the domain objects before integrating authentication with your application.
---

## Realm

A realm is a trusted authentication boundary configured by the operator. Database operations scope users, provider configuration and sessions to that realm. A browser cannot select a realm by sending a different user ID or request field.

The local example sets one `AUTH_REALM_ID`. Reuse its configured `Auth` instance for application routes. Do not construct an instance from an untrusted tenant parameter.

## User

A user is the local account identity. Its public ID is distinct from an email address or external provider subject. Email and display name may be absent for provider-only accounts.

Store application-owned records against the public user ID and the appropriate realm boundary. Apply your own roles, ownership checks and business permissions after authentication.

## Provider identity

An external identity binds a provider/connection and subject to a local user. An incoming Google, OIDC or SAML email is not automatically a local verified contact address. Matching email addresses never automatically merge accounts.

OIDC and SAML require trusted configuration and explicit activation. JIT admission is a policy decision, not an automatic consequence of accepting a signed provider response.

## Credential

Credentials establish control of an authentication method. Password verifiers, email proofs and passkey state have different purposes and lifecycles. None are application authorization roles.

Password enrollment begins from an existing verified account with fresh authentication. Password login does not create a new account. See the [password guide](/docs/guides/passwords/).

## Session

A session is durable server-side authentication state. The browser receives an opaque HttpOnly cookie; the database stores its verifier. The public session response is a user object, not an API token.

Default sessions expire after 30 minutes idle or seven days absolute. Revocation affects later validations across instances. A request already authorized may finish, so business transactions must still enforce their own authorization invariants.

## Authentication and authorization

`auth_axum::authenticate` answers whether the caller has a currently valid local session. It returns a user or an error. Your application then decides whether that user may perform the requested business action.

The [embedded example](/docs/embedding/) shows that boundary in a complete handler. The [browser guide](/docs/browser-integration/) shows how a same-origin UI checks its current session.
