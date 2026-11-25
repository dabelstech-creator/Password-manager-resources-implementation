# AuthPlatform implementation status

Branch: `feat/workos-device-oauth-backend`

## Added in this branch

- WorkOS AuthKit authorization-code exchange endpoint with PKCE verifier and exact configured iOS redirect URI.
- WorkOS discovery/JWKS-backed JWT verification with issuer, audience, expiry and not-before checks.
- PostgreSQL/Fluent persistence models and startup migration for users, devices, device challenges, OAuth device grants, access tokens and Telegram links.
- P-256 signed device-binding challenge flow, authenticated device listing and revocation.
- RFC 8628-style device authorization issuance, authenticated approval API, polling errors, one-time opaque access-token issuance, revocation and authorization-server metadata.
- Telegram shared-secret API for link challenges and redacted device listing; bot commands call the API and never deliver tokens.
- GitHub Actions Swift release-build workflow.

## Required deployment configuration

Set these in the API hosting platform, not in source control:

- `DATABASE_URL` — PostgreSQL URL.
- `WORKOS_CLIENT_ID` — AuthKit environment Client ID.
- `WORKOS_REDIRECT_URI_IOS` — exact callback URI registered in WorkOS and in the iOS app.
- `AUTHPLATFORM_PUBLIC_BASE_URL` — canonical public HTTPS API origin.
- `AUTHPLATFORM_OAUTH_CLIENT_ID` — registered device-flow public client ID.
- `AUTHPLATFORM_ALLOWED_SCOPES` — optional space-separated allowlist.
- `TELEGRAM_BOT_SHARED_SECRET` — high-entropy secret shared with the Telegram Serverless deployment.

Set `AUTHPLATFORM_API_URL` and `AUTHPLATFORM_TELEGRAM_SHARED_SECRET` in Telegram Serverless for @moredesaBot.

## Known gaps before production

- The browser-facing `/device` WorkOS sign-in/approval page and browser callback/session UX are not implemented; the protected approval API exists and requires an authenticated bearer token.
- The actual iOS URL scheme has not been confirmed from a checked-in iOS target. Do not assume the previously suggested `hundredlino://auth/callback` is registered.
- OAuth currently issues opaque one-hour access tokens only. Refresh-token rotation/reuse detection is not implemented.
- Rate limiting, comprehensive audit events, concurrency/transaction tests, and automated security tests still need to be added.
- Device challenge and grant state is persisted in PostgreSQL; production concurrency guarantees still need dedicated integration tests before enabling traffic.
- The Telegram bot source is wired to the API but has not been deployed to Telegram Serverless or tested against the live bot.
- CI is the compile authority for this branch; do not mark the code production-ready until the current Swift workflow succeeds and the remaining gaps are closed.

Never use Telegram chat as a password, OTP, recovery-code, or bearer-token collection channel.