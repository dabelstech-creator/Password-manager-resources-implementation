# AuthPlatform Telegram bot — @moredesaBot

This directory contains the Telegram Serverless project for the AuthPlatform prototype. It is intentionally isolated from the existing Swift/Vapor service.

## Current bot commands

- `/start`, `/help`
- `/status` — reports the actual integration gaps
- `/device` — explains that device binding is not implemented
- `/oauth` — explains that OAuth device authorization is not implemented

The handler does not collect or transmit passwords, API tokens, recovery codes, or one-time codes.

## Local setup

Requires Node.js 18+.

```sh
cd TelegramBot
npm install
npm run login
npm test
npm run status
```

`npm run login` prompts for the Telegram Serverless **CLI Access token** from BotFather → @moredesaBot → Serverless → CLI Access. This is distinct from the Telegram Bot API token. Enter it only in the interactive CLI prompt; never commit it or paste it into chat.

## Test and deploy

```sh
npx tgcloud run handlers/message '{ chat: { id: 12345 }, text: "/help" }'
npx tgcloud push
npx tgcloud status
```

Deploy only after logging in and reviewing `npx tgcloud diff`. Do not run `push` until the local project has been linked to the intended bot.

## Integration boundary

The existing repository's Vapor API currently exposes `GET /health` and `POST /auth/decision`. The decision endpoint is explicitly a prototype: it does not verify WebAuthn credentials, bind devices, issue OAuth device codes, exchange authorization codes, or issue sessions. The Telegram bot therefore reports these features as unavailable instead of pretending to complete authentication.

A secure next implementation requires defined AuthPlatform API contracts for device registration/binding/revocation and the OAuth 2.0 Device Authorization Grant, including user-code verification, polling interval enforcement, expiry, one-time token issuance, and authenticated client identity. Telegram messages must not be used to collect passwords or bearer tokens.
