# Telegram OIDC implementation status

Branch: `feat/telegram-oidc-kmp-device-integration`

## Implemented in this branch

- Telegram OIDC verifier using Telegram's published JWKS, exact issuer, configured audience, expiry, issued-at, not-before, and an explicit asymmetric algorithm allow-list.
- `POST /v1/auth/telegram` accepts a signed ID token, resolves a stable Telegram subject, and returns a short-lived opaque AuthPlatform bearer token. The raw ID token is not persisted.
- A provider identity table uniquely maps Telegram subjects to AuthPlatform users.
- A pre-existing, verified `/link` bot account link is reused when the OIDC subject matches the Telegram account ID.
- Existing P-256 challenge/bind/list/revoke endpoints accept the issued opaque session token through the common bearer-token resolver.
- A separate KMP client module scaffold uses the published `app.univera.telegramlogin:telegram-login:0.3.0` artifact and documents Android/iOS callback integration.
- CI workflow added for Swift build, KMP Android/iOS compilation, and Telegram bot syntax tests (workflow execution still pending).

## Identity model migration

The `AuthUser.workos_subject` field is now optional. Existing WorkOS subject values are preserved, and a new additive SQL migration removes the old NOT NULL constraint. Telegram subjects are stored separately in `telegram_oidc_identities` with a unique constraint; Telegram-only accounts do not receive fabricated WorkOS subjects.

The shared bearer resolver accepts opaque AuthPlatform tokens even if WorkOS is not configured. WorkOS JWT verification remains available when its client ID is configured.


## Not yet production-complete

- Browser device approval frontend and browser session bootstrap are not implemented. The API approval endpoint still requires an authenticated bearer token; the bot must not silently approve a device.
- Android package name, production signing fingerprint, iOS bundle ID, Apple Team ID, and both BotFather redirect hosts are not present in this repository. Host-app callback registration cannot be completed until those real values exist.
- The KMP module is a scaffold, not a finished Android/iOS application. The host apps do not exist in this repository, and callback round trips have not yet been device-tested.
- Device challenge consumption and OAuth grant approval/token issuance need transaction-level concurrency tests.
- Public auth rate limiting, security audit events, refresh-token rotation/reuse detection, and robust JWKS cache/rotation behavior need additional hardening.
- The Telegram Serverless bot handler is configured to call AuthPlatform; live bot deployment and integration tests have not been performed.

## Required deployment variables

- `TELEGRAM_LOGIN_CLIENT_ID`: Telegram Login/OIDC client ID configured in BotFather. It is not the Telegram Bot API token.
- `DATABASE_URL`: PostgreSQL database.
- `AUTHPLATFORM_PUBLIC_BASE_URL`, `AUTHPLATFORM_DEVICE_VERIFICATION_URL`, `AUTHPLATFORM_OAUTH_CLIENT_ID`: existing device authorization configuration.
- `TELEGRAM_BOT_SHARED_SECRET`: API-side service secret; configure the matching `AUTHPLATFORM_TELEGRAM_SHARED_SECRET` in Telegram Serverless.
- WorkOS variables remain required only for WorkOS AuthKit login clients.

Do not deploy until migrations, all CI jobs, platform callbacks, browser approval, and security gates pass.
