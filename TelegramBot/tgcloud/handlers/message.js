import { api, db, fetch } from 'sdk';
import { telegramBotUsers } from '../schema.js';

const HELP = [
  'AuthPlatform — @moredesaBot',
  '',
  'Commands:',
  '/start — introduction',
  '/help — show commands',
  '/status — API integration readiness',
  '/link — link this Telegram account to AuthPlatform',
  '/device — list devices on your linked AuthPlatform account',
  '/oauth — instructions for approving a device sign-in',
  '/approve CODE — inspect a pending device request',
  '/confirm CODE — approve the inspected device request',
  '/deny CODE — deny a pending device request',
  '',
  'Security: never send passwords, recovery codes, API tokens, or one-time login codes to this bot.',
].join('\n');

function configuration() {
  const base = process.env.AUTHPLATFORM_API_URL?.replace(/\/+$/, '');
  const secret = process.env.AUTHPLATFORM_TELEGRAM_SHARED_SECRET;
  if (!base || !secret) throw new Error('Telegram API integration is not configured');
  return { base, secret };
}

async function apiRequest(path, options = {}) {
  const { base, secret } = configuration();
  const response = await fetch(`${base}${path}`, {
    ...options,
    headers: {
      'X-AuthPlatform-Telegram-Secret': secret,
      'Content-Type': 'application/json',
      ...(options.headers ?? {}),
    },
  });
  if (!response.ok) throw new Error(`AuthPlatform API returned HTTP ${response.status}`);
  return response.status === 204 ? null : response.json();
}

async function rememberTelegramUser(message) {
  if (message.from?.id == null || message.chat?.id == null) return;
  const now = Math.floor(Date.now() / 1000);
  const telegramUserId = String(message.from.id);
  await db.insert(telegramBotUsers)
    .values({
      telegramUserId,
      chatId: String(message.chat.id),
      languageCode: message.from.language_code ?? null,
      firstSeenAt: now,
      lastSeenAt: now,
    })
    .onConflictDoUpdate({
      target: telegramBotUsers.telegramUserId,
      set: {
        chatId: String(message.chat.id),
        languageCode: message.from.language_code ?? null,
        lastSeenAt: now,
      },
    })
    .run();
}

async function responseFor(message) {
  const parts = (message.text ?? '').trim().split(/\s+/);
  const command = parts[0].split('@')[0].toLowerCase();
  const userCode = parts[1] ?? '';
  const telegramUserID = message.from?.id == null ? null : String(message.from.id);

  switch (command) {
    case '/start':
      return 'Welcome to AuthPlatform. Use /link to connect this Telegram account after signing in to AuthPlatform, /device to view linked devices, and /help for commands.';
    case '/help':
      return HELP;
    case '/status':
      try {
        const result = await apiRequest('/v1/telegram/status');
        return `AuthPlatform API: ${result.status}\nService: ${result.service}`;
      } catch {
        return 'AuthPlatform API is not reachable or Telegram service credentials are not configured.';
      }
    case '/link':
      if (!telegramUserID) return 'Telegram user identity is unavailable for this message.';
      try {
        const result = await apiRequest('/v1/telegram/link-challenges', {
          method: 'POST',
          body: JSON.stringify({ telegram_user_id: telegramUserID }),
        });
        return [
          'Account-link verification',
          `Your one-time link code is: ${result.code}`,
          '',
          'Open the AuthPlatform app or website, sign in to AuthPlatform, and enter this code in the Telegram linking screen.',
          'The code expires in 10 minutes. This bot will never ask for your password or login token.',
        ].join('\n');
      } catch {
        return 'Could not create a link code. Check the AuthPlatform API configuration and try again.';
      }
    case '/device':
      if (!telegramUserID) return 'Telegram user identity is unavailable for this message.';
      try {
        const result = await apiRequest(`/v1/telegram/devices?telegram_user_id=${encodeURIComponent(telegramUserID)}`);
        if (!result.devices?.length) return 'No active devices are registered on the linked AuthPlatform account.';
        return ['Your active AuthPlatform devices:', ...result.devices.map((device, index) =>
          `${index + 1}. ${device.label} — ${device.platform} (ID: ${device.id})`
        )].join('\n');
      } catch {
        return 'This Telegram account is not linked, or the AuthPlatform API is unavailable. Use /link first.';
      }
    case '/oauth':
      return 'To sign in on a TV, CLI, or other device, start the OAuth device authorization flow in that device’s AuthPlatform client. It will display a short user code. Send /approve CODE to inspect the requesting client and scopes, then /confirm CODE to approve or /deny CODE to reject. Only a Telegram account already linked to AuthPlatform can approve. The bot never issues or delivers access tokens.';
    case '/approve':
      if (!telegramUserID || !userCode) return 'Usage: /approve CODE — enter the short code shown on the device.';
      try {
        const result = await apiRequest(`/v1/telegram/device-authorizations?telegram_user_id=${encodeURIComponent(telegramUserID)}&user_code=${encodeURIComponent(userCode)}`);
        return [
          'Pending AuthPlatform device request',
          `Client: ${result.client_id}`,
          `Requested scopes: ${result.scopes || '(none)'}`,
          `Expires: ${new Date(result.expires_at).toISOString()}`,
          '',
          `If you recognize this request, send /confirm ${userCode}. Otherwise send /deny ${userCode}.`,
        ].join('\n');
      } catch {
        return 'No valid pending request was found, or this Telegram account is not linked. Check the code and try again.';
      }
    case '/confirm':
    case '/deny':
      if (!telegramUserID || !userCode) return `Usage: ${command} CODE`;
      try {
        await apiRequest('/v1/telegram/device-approval', {
          method: 'POST',
          body: JSON.stringify({
            telegram_user_id: telegramUserID,
            user_code: userCode,
            approve: command === '/confirm',
          }),
        });
        return command === '/confirm'
          ? 'Device request approved. The requesting device can now complete sign-in.'
          : 'Device request denied.';
      } catch {
        return 'Could not process this device request. It may be expired, already handled, or this Telegram account is not linked.';
      }
    default:
      return 'I did not recognize that command. Use /help. Do not send passwords or authentication codes here.';
  }
}

export default async function (message) {
  if (!message?.chat?.id || typeof message.text !== 'string') return;

  // SQLite stores only Telegram-side operational metadata. Identity, account
  // links, devices, and OAuth authorization remain owned by AuthPlatform.
  try {
    await rememberTelegramUser(message);
  } catch {
    console.error('Could not persist Telegram bot user metadata');
  }

  let text;
  try {
    text = await responseFor(message);
  } catch {
    text = 'AuthPlatform integration is temporarily unavailable. Try again later.';
  }
  await api.sendMessage({ chat_id: message.chat.id, text });
}
