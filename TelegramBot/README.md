# AuthPlatform Telegram bot — @moredesaBot

This directory contains the Telegram Serverless handler for the AuthPlatform backend. It communicates with AuthPlatform over HTTPS and uses the bot's managed SQLite database only for bot-local operational metadata.

## Database ownership

The system uses a deliberate hybrid model:

| Data | Authoritative store |
| --- | --- |
| Telegram chat preferences and minimal bot-user metadata | Telegram Serverless managed SQLite |
| WorkOS and Telegram identities | AuthPlatform PostgreSQL |
| AuthPlatform user accounts and account links | AuthPlatform PostgreSQL |
| Device public keys, registrations, and revocations | AuthPlatform PostgreSQL |
| OAuth device grants and access-token hashes | AuthPlatform PostgreSQL |

`tgcloud/schema.js` declares the `telegram_bot_users` table. It stores Telegram user ID, chat ID, language code, notification preference, and first/last-seen timestamps. It does not store passwords, OIDC ID tokens, bearer tokens, link codes, private keys, device records, or OAuth grants.

The Serverless SQLite database is managed by Telegram and is accessible only from Telegram Serverless modules through `sdk/db`. It is not an external PostgreSQL-compatible connection string and must not be configured as AuthPlatform's `DATABASE_URL`. The Swift/Vapor backend continues to use PostgreSQL/Fluent as the source of truth for authentication and authorization.

Schema declaration and migration are separate steps: deploying `tgcloud/schema.js` registers the schema; `npx tgcloud migrate` applies the reviewed SQLite migration. Neither command is run as part of this source change.

## Bot commands

- `/start`, `/help` — introduction and usage
- `/status` — check the AuthPlatform API integration
- `/link` — create a short-lived account-link challenge
- `/device` — list devices on the linked AuthPlatform account
- `/approve CODE` — preview a pending device sign-in request
- `/confirm CODE` — approve the reviewed request
- `/deny CODE` — deny the reviewed request
- `/oauth` — explain browser and Telegram approval

Telegram-based device approval uses the authenticated AuthPlatform service endpoint. The bot derives the Telegram user ID from the incoming Telegram update, previews the request, and requires a separate `/confirm CODE` or `/deny CODE` action. AuthPlatform verifies the shared service secret, resolves the Telegram account link, and atomically transitions a pending grant. The bot accepts only the OAuth device user code explicitly shown by the AuthPlatform client; it never requests passwords, recovery codes, bearer tokens, or unrelated one-time login codes.

## AuthPlatform API configuration

Set these variables in the Telegram Serverless runtime for this bot:

- `AUTHPLATFORM_API_URL` — the public HTTPS base URL of the AuthPlatform API, without a trailing slash
- `AUTHPLATFORM_TELEGRAM_SHARED_SECRET` — the same high-entropy service secret configured as `TELEGRAM_BOT_SHARED_SECRET` on the API service

The API authenticates bot requests with the `X-AuthPlatform-Telegram-Secret` header. Do not place either secret in source control, this README, or chat messages.

On the API service, configure:

- `TELEGRAM_BOT_SHARED_SECRET` — same value as the bot runtime's `AUTHPLATFORM_TELEGRAM_SHARED_SECRET`
- `DATABASE_URL` — PostgreSQL connection string
- `TELEGRAM_LOGIN_CLIENT_ID` — the OIDC Client ID issued by BotFather's Login Widget; this is not a Bot API token
- `AUTHPLATFORM_PUBLIC_BASE_URL`, `AUTHPLATFORM_DEVICE_VERIFICATION_URL`, and `AUTHPLATFORM_OAUTH_CLIENT_ID` for the OAuth device flow

The API-side secret and bot-side secret must match exactly. Configure secrets only through the relevant hosting provider's secret manager.

## Local setup and validation

Requires Node.js 18+ and the Telegram Serverless CLI.

```sh
cd TelegramBot
npm install
npm run login
npm test
npm run status
```

`npm run login` prompts for the Telegram Serverless **CLI Access token** from BotFather → @moredesaBot → Serverless → CLI Access. This is separate from the Telegram Bot API token and the Telegram Login OIDC Client Secret. Enter it only in the interactive CLI prompt; never commit it or paste it into chat.

## Test and deploy

```sh
npx tgcloud run handlers/message '{ chat: { id: 12345 }, text: "/help" }'
npx tgcloud diff
npx tgcloud push
npx tgcloud status
```

Review the diff and confirm the project is linked to the intended bot before `push`. After deploying a schema change, inspect the migration plan before explicitly running `npx tgcloud migrate`. Do not run either command until the migration is reviewed and separately approved. The bot deployment is not complete until the deployed handler is verified against a staging AuthPlatform API.

## Security and production boundary

- Bot-originated API requests require the shared service secret and a previously linked Telegram account.
- Telegram approval requires the exact high-entropy shared secret and a Telegram account already linked to the AuthPlatform user.
- Device approval codes are short-lived and single-use; users must never approve a request they did not initiate.
- The bot does not create an AuthPlatform session or expose bearer tokens.
- The API's Telegram OIDC endpoint verifies signed ID tokens against Telegram's published JWKS, issuer, audience, and time claims. The full BotFather OIDC registration and real client credentials still need to be configured.
- The KMP module is an integration scaffold; native Android/iOS secure-key storage and host-app callback wiring remain incomplete.
- Browser approval is served at `/device` and uses WorkOS AuthKit PKCE. Register the exact callback `https://password-manager-resources-implementation.onrender.com/device/callback` in WorkOS and set `WORKOS_REDIRECT_URI_WEB` on AuthPlatform.
- End-to-end staging verification, native secure-key storage, and mobile callback wiring remain production gates.

Never deploy this bot against production until the API, PostgreSQL migrations, Serverless SQLite migration, OIDC client registration, mobile callbacks, browser approval, and security tests have been verified in staging.
