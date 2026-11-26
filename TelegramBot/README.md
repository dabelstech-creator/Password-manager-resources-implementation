# AuthPlatform Telegram bot — @moredesaBot

This directory contains the Telegram Serverless handler for the AuthPlatform backend. It is isolated from the Swift/Vapor API and communicates with it over HTTPS.

## Bot commands

The BotFather command list is configured for these commands:

- `/start`, `/help` — introduction and usage
- `/status` — check the AuthPlatform API integration
- `/link` — create a short-lived account-link challenge
- `/device` — list devices on the linked AuthPlatform account
- `/oauth` — explain device sign-in approval
- `/approve CODE` — inspect a pending device authorization (client and scopes)
- `/confirm CODE` — approve the inspected request
- `/deny CODE` — reject a pending request

The approval flow is two-step: users inspect the request before confirming it. The bot never returns access tokens and must not collect passwords, recovery codes, API tokens, or one-time login credentials.

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

Review the diff and confirm the project is linked to the intended bot before `push`. The bot deployment is not complete until the deployed handler is verified against a staging AuthPlatform API.

## Security and production boundary

- Bot-originated API requests require the shared service secret and a previously linked Telegram account.
- Device approvals require a pending, unexpired user code and an explicit confirmation or denial.
- The bot does not create an AuthPlatform session or expose bearer tokens.
- The API's Telegram OIDC endpoint verifies signed ID tokens against Telegram's published JWKS, issuer, audience, and time claims. The full BotFather OIDC registration and real client credentials still need to be configured.
- The KMP module is an integration scaffold; native Android/iOS secure-key storage and host-app callback wiring remain incomplete.
- Browser-based approval UI and end-to-end staging verification remain production gates.

Never deploy this bot against production until the API, database migrations, OIDC client registration, mobile callbacks, browser approval, and security tests have been verified in staging.
