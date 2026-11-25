# AuthPlatform production identity architecture

Status: implementation plan and API contract. This document is not evidence that the endpoints are implemented or production-ready.

## Selected identity authority

Use **WorkOS AuthKit** as the primary upstream identity provider for AuthPlatform account authentication. AuthPlatform remains the relying party and owns its device registry, OAuth device-authorization state, application sessions, authorization policy, and audit trail.

Keep identity-provider integration behind an `IdentityTokenVerifier` abstraction. This avoids coupling device records to WorkOS-specific identifiers and permits existing Microsoft External ID or local-account sign-in methods to be preserved where they already exist. Map a verified external identity to a stable internal `user_id`; never use an email address as the durable account key.

For WorkOS access tokens:
- Load OpenID Connect discovery from `https://api.workos.com/user_management/{WORKOS_CLIENT_ID}/.well-known/openid-configuration`.
- Validate JWT signature against the published JWKS, exact configured issuer, audience/client ID, expiry, not-before, and allowed signing algorithm.
- Cache discovery/JWKS with bounded refresh and key-rotation handling.
- Reject unsigned tokens, unknown key IDs after refresh, wrong issuer/audience, expired tokens, and tokens with missing subject.
- Never trust an identity or user ID supplied in a request body.
- Keep WorkOS API secrets server-side only. Native iOS clients use Authorization Code + PKCE; do not embed a WorkOS secret in an app.

Required deployment configuration (values are intentionally not included here):
- `WORKOS_CLIENT_ID`
- `WORKOS_API_KEY` (server-side secret)
- `WORKOS_REDIRECT_URI_IOS`
- `DATABASE_URL` (PostgreSQL)
- `AUTHPLATFORM_PUBLIC_BASE_URL`
- `AUTHPLATFORM_SIGNING_KEY` from a managed secret store/KMS, not source control
- `TELEGRAM_BOT_SHARED_SECRET` for authenticated bot-to-API calls, stored as a platform secret

The WorkOS account exists, but the Client ID and iOS redirect URI were previously not configured. These must be created in WorkOS before end-to-end identity verification can pass.

## Device binding API

All account-scoped endpoints require a verified AuthPlatform session derived from a validated WorkOS (or explicitly supported alternate provider) identity. The server derives `user_id` from that session.

### Endpoints

- `POST /v1/devices/challenges` — issue a short-lived, single-use challenge bound to the authenticated user, requested device metadata, and operation.
- `POST /v1/devices/bind` — verify proof of possession of the device public key over the challenge; atomically consume the challenge and register the device.
- `GET /v1/devices` — list the authenticated user's devices (never expose private keys or raw credential material).
- `DELETE /v1/devices/{device_id}` — revoke a device owned by the authenticated user; reject cross-account IDs.
- `POST /v1/devices/{device_id}/challenge` — issue a fresh challenge for a cryptographic re-verification operation.

### Required controls

- Generate challenges with a cryptographically secure RNG; store only a hash; enforce expiry and one-time consumption transactionally.
- Verify signatures using a supported asymmetric algorithm and canonical signed payload including challenge, user, device ID, audience, and expiry.
- Store public keys, algorithm, key thumbprint, platform, display label, created/last-seen/revoked timestamps, and key-rotation history.
- Enforce unique key thumbprints per account and prevent silent reassignment across accounts.
- Rebinding requires recent step-up authentication and proof of possession of the new key; revocation must invalidate associated refresh-token families.
- iOS: use Secure Enclave-backed keys where supported. Desktop/browser clients: use platform WebCrypto/OS keystore and WebAuthn where appropriate. Do not claim a browser fingerprint is cryptographic device binding.
- Apply rate limits to challenge creation and failed proofs. Audit bind, failed bind, rebind, list, and revoke events without logging secrets.

## OAuth 2.0 Device Authorization Grant

Implement RFC 8628 as an AuthPlatform authorization-server capability. WorkOS authenticates the human at the verification page; AuthPlatform owns the device grant and issues its own scoped application tokens after approval.

### Endpoints

- `POST /oauth/device_authorization` — validate registered `client_id`, requested scopes and policy; return opaque `device_code`, human-friendly `user_code`, `verification_uri`, `expires_in`, and `interval`.
- `GET /device` — verification page; user signs in through WorkOS AuthKit, enters the user code, reviews client/device/scope details, and explicitly approves or denies.
- `POST /oauth/token` — accept `urn:ietf:params:oauth:grant-type:device_code`, client identity, and device code; return RFC 8628 errors while pending/slow/denied/expired; issue tokens exactly once after approval.
- `POST /oauth/revoke` — revoke supported tokens/token families.
- `GET /.well-known/oauth-authorization-server` — publish issuer, endpoints, supported grant types, scopes and token auth methods.

### Required controls

- Use cryptographically random device codes; store only hashes. Generate user codes with sufficient entropy, collision checks, and normalization.
- Persist grant state in PostgreSQL; do not use process memory as the source of truth.
- Enforce expiry, per-client and per-IP rate limits, minimum polling interval, RFC 8628 `authorization_pending`, `slow_down`, `access_denied`, and `expired_token` behavior.
- Use atomic database transitions so concurrent polls cannot issue multiple token sets.
- Require explicit authenticated approval and show the client name, requested scopes, and device details. Denial is terminal.
- Issue short-lived, audience-restricted access tokens and rotating, hashed refresh tokens only if the registered client is eligible. Bind refresh-token families to device public keys where proof-of-possession support is implemented.
- Store token identifiers/hashes and revocation state; never store plaintext refresh tokens.
- Do not treat a Telegram message, Telegram username, or user-supplied account ID as approval.

## Telegram integration: @moredesaBot

Telegram is an interaction surface, not an identity provider or bearer-token wallet.

- `/device` should show the user's linked devices and offer a web-based secure device-management link. Binding/revocation must be completed in the authenticated AuthPlatform web/app flow.
- `/oauth` should start a registered, explicitly configured device authorization request and return the user code and verification URL. It must not return the device code or any access/refresh token to the chat.
- `/status` should report API health and feature readiness, not infer account authentication from Telegram identity.
- Link Telegram to an AuthPlatform account only after the user authenticates with WorkOS on the official verification page and confirms linking. Store Telegram numeric ID as a notification/contact association, not as proof of identity.
- Authenticate bot-to-API requests with a rotated server-side shared secret or signed service credential; allowlist operations and rate-limit by bot identity. Store all secrets in deployment secret configuration, never in git.

## Persistence model

PostgreSQL tables (with migrations and foreign keys):
- `users` — internal stable subject and lifecycle state.
- `external_identities` — provider + issuer + subject unique mapping.
- `devices` — owner, public key, thumbprint, platform metadata, lifecycle timestamps.
- `device_challenges` — challenge hash, owner, operation, expiry, consumed timestamp.
- `oauth_clients` — client ID, display metadata, allowed scopes, token policy, public/confidential classification.
- `device_authorizations` — device-code hash, user-code hash, client, scopes, expiry, polling interval, approval/denial state, user and device association.
- `refresh_token_families` — token hashes, device binding, rotation/reuse detection, revocation.
- `audit_events` — append-only security events with redacted metadata.

Use migrations, transaction boundaries, indexes on hashed lookup keys, uniqueness constraints, and retention policies. Do not store passwords or third-party provider secrets in these tables.

## Production gate

Do not enable production traffic until all of the following are true:
1. WorkOS Client ID, callback URLs, allowed origins, and production domain are configured and verified.
2. PostgreSQL migrations and backup/restore are tested.
3. JWT/JWKS validation, key rotation, and issuer/audience negative tests pass.
4. Device proof-of-possession, cross-account access, replay, expiry, revocation, and concurrency tests pass.
5. RFC 8628 conformance tests cover pending, slow_down, approval, denial, expiry, and exactly-once token issuance.
6. Rate limits, structured redacted logs, monitoring, alerting, secret rotation, and incident/revocation procedures are configured.
7. iOS, browser, and desktop clients pass end-to-end enrollment and revocation tests.
8. Telegram integration is tested with a non-production bot and cannot issue or expose tokens in chat.

## Standards and upstream documentation

- WorkOS AuthKit session/JWT validation: https://workos.com/docs/authkit/sessions
- OAuth 2.0 Device Authorization Grant (RFC 8628): https://www.rfc-editor.org/rfc/rfc8628
