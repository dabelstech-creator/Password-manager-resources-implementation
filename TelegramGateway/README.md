# Render Telegram Gateway for AuthPlatform

This is an isolated Node.js webhook service for @moredesaBot. It keeps application credentials in Render environment variables and calls the existing AuthPlatform Telegram API over HTTPS. It does not replace the Telegram Serverless project or switch the bot webhook.

## Runtime configuration

Create a separate Render Web Service from this repository with:

- Runtime: Docker
- Branch: `feat/render-telegram-gateway` for preview validation
- Root Directory: `TelegramGateway`
- Dockerfile: `Dockerfile`
- Health Check Path: `/health`
- Start command: use the Dockerfile default

Set these values in the Render service's Environment page. Never commit real values or paste them into chat.

| Variable | Purpose |
|---|---|
| `TELEGRAM_BOT_TOKEN` | BotFather Bot API token for @moredesaBot |
| `TELEGRAM_WEBHOOK_SECRET` | Random webhook secret, at least 16 characters |
| `AUTHPLATFORM_API_URL` | Canonical HTTPS origin of the AuthPlatform API |
| `TELEGRAM_BOT_SHARED_SECRET` | Must match AuthPlatform's `TELEGRAM_BOT_SHARED_SECRET` |
| `PORT` | Render supplies this automatically; local default is 10000 |

The gateway authenticates to AuthPlatform with the `X-AuthPlatform-Telegram-Secret` header. It does not persist identity or device data locally.

## Routes and commands

- `GET /health` — liveness only; does not claim database readiness.
- `POST /telegram/webhook` — Telegram webhook; validates Telegram's `X-Telegram-Bot-Api-Secret-Token` header.
- `/start`, `/help`, `/status`, `/link`, `/device`, `/oauth`.

The gateway never asks for passwords, OTPs, recovery codes, or bearer tokens. Access tokens are never sent through Telegram. The `/link` command creates a short-lived code; the user must claim it through an authenticated AuthPlatform session.

## Local checks

Requires Node.js 22+.

```sh
npm test
npm run check
docker build -t authplatform-telegram-gateway .
```

## Webhook cutover — intentionally not performed

After a Render service is separately approved, use Telegram's `setWebhook` API with:

- URL: `https://<render-service-host>/telegram/webhook`
- `secret_token`: the value configured as `TELEGRAM_WEBHOOK_SECRET`
- `allowed_updates`: `["message"]`

Do not set the webhook until the gateway has passed live health and authenticated API checks and the owner explicitly approves cutover. Setting the webhook replaces the existing Serverless-managed webhook. Preserve the Serverless project and its state until cutover is verified and a rollback plan is agreed.

## Operational limits

Update de-duplication is process-local and best-effort. For multi-instance or restart-safe delivery, add a durable idempotency store before scaling horizontally. Configure Render with one instance until that work is completed. Rate limiting and durable webhook replay protection are additional production hardening tasks.
