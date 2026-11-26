# Browser and Telegram device approval

## Browser flow

The AuthPlatform browser verification page is served at:

- `GET /device`
- `GET /device/login` starts WorkOS AuthKit authorization-code + PKCE
- `GET /device/callback` validates the one-time state cookie, exchanges the code, and creates an opaque HttpOnly browser session
- `POST /device/approve` approves or denies a pending device grant for the signed-in WorkOS user
- `GET /device/logout` clears the browser session cookie

The browser session cookie is Secure, HttpOnly, SameSite=Lax, and expires after one hour. The page does not store access tokens in JavaScript or local storage.

Configure the WorkOS application with this exact redirect URI:

`https://password-manager-resources-implementation.onrender.com/device/callback`

Set `WORKOS_REDIRECT_URI_WEB` to that value in the AuthPlatform Render service. If the variable is omitted, AuthPlatform derives the same callback from `AUTHPLATFORM_PUBLIC_BASE_URL`. Set `AUTHPLATFORM_DEVICE_VERIFICATION_URL` to `https://password-manager-resources-implementation.onrender.com/device` so OAuth clients open this page. Keep the existing iOS callback `WORKOS_REDIRECT_URI_IOS` separate.

## Telegram service approval

The bot service must send `X-AuthPlatform-Telegram-Secret` on both preview and approval calls. The server compares it in constant time, resolves the supplied Telegram numeric ID through `telegram_links`, and only then attempts the grant transition. The bot must derive the Telegram ID from the authenticated Telegram update; never accept an ID supplied by an end user as authoritative.

- `GET /v1/telegram/device-authorizations?telegram_user_id=...&user_code=...` previews a pending request for a linked Telegram account.
- `POST /v1/telegram/device-approval` accepts `telegram_user_id`, `user_code`, and `approve`.

Both browser and Telegram approval use a conditional database update from `pending` and reject competing decisions with HTTP 409. Expired, already-handled, or malformed codes cannot transition a grant.

## Staging integration and concurrency test

Run only against a staging AuthPlatform deployment with disposable test data:

```powershell
$env:AUTHPLATFORM_BASE_URL = "https://your-staging-host"
$env:AUTHPLATFORM_OAUTH_CLIENT_ID = "your-device-client-id"
$env:AUTHPLATFORM_ACCESS_TOKEN = "a valid staging bearer token"
python scripts/device-approval-concurrency-test.py
```

Optional Telegram invalid-secret check:

```powershell
$env:TELEGRAM_BOT_SHARED_SECRET = "configured staging secret"
$env:TELEGRAM_USER_ID = "a linked staging Telegram numeric ID"
```

The harness creates a device grant, races opposing browser decisions, then concurrently polls its token endpoint and asserts no more than one token is issued. It also verifies an invalid Telegram service secret is rejected. It does not modify production data unless pointed at production; do not run it against production.
