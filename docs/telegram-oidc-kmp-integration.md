# Telegram OIDC and cross-device integration

## Decision

AuthPlatform remains the single identity, authorization, and device-registry authority. The three upstream repositories are inputs to one integration, not three services to deploy:

| Upstream | Intended use | Not adopted |
|---|---|---|
| `andy-takker/tg-auth` | Reference for Telegram OIDC ID-token validation, JWKS caching, identity mapping, and rate-limited login endpoints. | Its Litestar/SQLite app, cookie-session implementation, and independent user database. |
| `tergeoo/telegram-go` | Reference for Telegram OIDC code+PKCE exchange, claim normalization, and bot state-machine interfaces where a Go worker is actually needed. | Its in-memory session store as production persistence; its Login Widget HMAC flow as a substitute for OIDC. |
| `Univera-LLC/kmp-telegram-login` | Android/iOS client SDK for Telegram native login using OAuth2 + PKCE. | Treating the community SDK as Telegram-maintained or assuming its redirect configuration is already registered. |

The AuthPlatform backend is Swift/Vapor with Fluent/PostgreSQL. Do not add a parallel Python or Go identity database. The existing Telegram Serverless bot `@moredesaBot` remains the bot delivery surface and calls the authenticated AuthPlatform Telegram service endpoints.

## Authentication and account model

1. The KMP app invokes Telegram native login and receives a Telegram-signed OIDC `id_token`.
2. The app sends only that ID token to `POST /v1/auth/telegram` over HTTPS.
3. AuthPlatform verifies the JWT signature against `https://oauth.telegram.org/.well-known/jwks.json`, and validates exact issuer `https://oauth.telegram.org`, configured audience/client ID, expiry, issued-at, and required subject. Reject unsigned, symmetric, wrong-audience, expired, or malformed tokens.
4. AuthPlatform upserts a Telegram identity keyed by the stable OIDC `sub` claim. Do not key identity by username, phone number, display name, or client-supplied Telegram profile fields.
5. A Telegram-only account receives an AuthPlatform session/token under the same token validation path used by WorkOS users. If the Telegram identity is being attached to an existing WorkOS account, require an authenticated account-link confirmation and enforce a unique Telegram subject.
6. The app generates a P-256 key pair in platform-protected storage (Android Keystore / iOS Keychain with Secure Enclave where available). The private key never leaves the device.
7. The app calls the existing device challenge and bind endpoints. AuthPlatform stores the public key and accepts registration only after verifying the signature over the server-issued, short-lived, one-time challenge.
8. Desktop/browser clients use the existing OAuth device authorization flow. The user reviews and approves the device on an authenticated web page; the bot may notify or display status but must never collect credentials or issue bearer tokens.

## Required backend changes

The current `AuthUser.workos_subject` is non-nullable, so it cannot represent a Telegram-only user. Before enabling Telegram-native sign-in:

- Make the WorkOS subject optional in the user model and database migration, retaining a unique constraint for non-null values.
- Add a `telegram_identities` table with a unique `telegram_subject`, `user_id` foreign key, provider issuer, created/updated timestamps, and optional verified profile metadata. Keep the OIDC `sub` as the durable key.
- Add a Telegram OIDC verifier with bounded JWKS cache lifetime, key-rotation handling, explicit algorithm allow-list, issuer/audience/time validation, and fail-closed network/error behavior.
- Add `TELEGRAM_LOGIN_CLIENT_ID` as server-side configuration. This is the Telegram Login/OIDC client ID configured in BotFather; it is not the bot API token and must not be guessed from the bot username.
- Add `POST /v1/auth/telegram` accepting `{ "id_token": "..." }`. Return an AuthPlatform session response, never echo the ID token or expose it in logs.
- Refactor bearer authentication so AuthPlatform-issued opaque device tokens remain valid even when WorkOS is not configured; do not make Telegram-only users depend on a WorkOS client ID.
- Add account-link and unlink rules. A Telegram subject may belong to only one AuthPlatform user. Linking must require a current authenticated session and one-time confirmation; unlinking must require a remaining recovery/authentication method.
- Keep the existing BotFather serverless shared-secret endpoints separate from public user authentication. Validate service credentials with constant-time comparison, rate-limit public auth endpoints, and never trust a raw Telegram user ID supplied by an unauthenticated client.
- Add audit events for login success/failure, link/unlink, device bind/revoke, and device authorization approval/denial. Do not log ID tokens, bot tokens, private keys, link codes, or bearer tokens.

## KMP client integration

Use the published SDK only after confirming its exact version and release artifact. The upstream README documents Kotlin 2.4.x, Android minSdk 23, and iOS 15 requirements; confirm those constraints against the actual app toolchain before adding it.

- Register the Android package name + production app-signing SHA-256 fingerprint and the iOS bundle ID + Apple Team ID in BotFather.
- Obtain the separate Android and iOS redirect hosts from BotFather. Android's documented App Link includes `/tglogin`; iOS uses its own Universal Link host. Do not reuse the WorkOS iOS callback URI.
- Configure the SDK with the BotFather client ID and platform-specific redirect URI. Keep client ID non-secret; never embed bot API token or client secret in the app.
- Forward Android `onNewIntent` and iOS `onOpenURL` callbacks to the SDK's `handle` method.
- Post `Success.idToken` to AuthPlatform. On success, bind the device using a platform-backed P-256 private key. On cancel/error, do not create a session or device record.
- Use verified Android App Links and iOS Universal Links in production. Custom schemes are development/fallback only and must be registered and tested explicitly.

## Telegram bot integration

Keep `@moredesaBot` as a notification and account-management interface:

- `/link` creates a short-lived challenge through the service-authenticated endpoint; user claims it in an already authenticated AuthPlatform session.
- `/device` returns only redacted device metadata for the linked Telegram identity.
- `/oauth` explains the browser approval flow; it does not approve on behalf of the user.
- Add an explicit confirmation step before any future revoke or approval command. A Telegram message alone must not be treated as cryptographic device possession.
- Never accept passwords, WorkOS tokens, Telegram ID tokens, recovery codes, private keys, or device bearer tokens in chat.

## Cross-platform device identity

Use one device record format across iOS, Android, desktop, and browser clients:

- stable server-generated device UUID;
- account UUID;
- platform and user-editable label;
- public P-256 key and thumbprint;
- creation / last-seen / revoked timestamps;
- optional app version and device class metadata.

The server challenge must be random, short-lived, one-use, and bound to the account and submitted public key. Bind operations need a database transaction/conditional update to prevent replay and concurrent duplicate registration. Revocation must invalidate all credentials associated with the device. Browser extensions should use a non-exportable WebCrypto key where supported; desktop clients should use the OS credential store. Do not pretend a browser key has Secure Enclave/Keystore guarantees.

## API contract (proposed)

### Telegram login

`POST /v1/auth/telegram`

```json
{ "id_token": "<Telegram OIDC ID token>" }
```

Response shape should match the AuthPlatform session contract and include the AuthPlatform user ID and token expiry. The ID token is input evidence only; it is not an AuthPlatform API bearer token.

### Device binding

Reuse existing endpoints:

- `POST /v1/devices/challenges`
- `POST /v1/devices/bind`
- `GET /v1/devices`
- `DELETE /v1/devices/{deviceID}`

The client signs the exact canonical challenge payload using the private key corresponding to the submitted public key.

### Device authorization

Reuse existing:

- `POST /oauth/device_authorization`
- `POST /device/approve`
- `POST /oauth/token`
- `POST /oauth/revoke`

Before production, implement a real browser approval UI with explicit client name, requested scopes, and approve/deny controls. The bot is not the approval UI.

## Security and release gates

- [ ] Confirm BotFather OIDC client ID and Android/iOS redirect registrations for `@moredesaBot`.
- [ ] Add Telegram-only identity migration and unique-subject constraints.
- [ ] Add Telegram OIDC verifier tests: valid token, wrong issuer, wrong audience, expired token, future `iat`, bad signature, unknown key, JWKS rotation, and malformed claims.
- [ ] Add account-link tests for duplicate subject, expired/replayed challenge, cross-account conflict, and unlink recovery requirements.
- [ ] Add transaction/concurrency tests for challenge consumption, device binding, grant approval, and one-time token issuance.
- [ ] Add Android and iOS build + callback tests with real registered app identifiers.
- [ ] Add desktop/browser device authorization tests and approval UI.
- [ ] Add rate limiting, audit events, refresh-token rotation/reuse detection, and credential revocation.
- [ ] Verify Render readiness and database migration against a staging database before production.
- [ ] Keep PRs draft and do not merge or deploy until all release gates pass.

## Source repositories

- https://github.com/andy-takker/tg-auth
- https://github.com/tergeoo/telegram-go
- https://github.com/Univera-LLC/kmp-telegram-login

All upstream projects should be pinned to reviewed commit SHAs before vendoring or depending on them. Review each upstream license and security posture before copying source.