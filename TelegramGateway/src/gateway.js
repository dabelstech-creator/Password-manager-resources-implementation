const HELP = [
  'AuthPlatform — @moredesaBot',
  '',
  'Commands:',
  '/start — introduction',
  '/help — show commands',
  '/status — check AuthPlatform connectivity',
  '/link — create a short-lived account-link code',
  '/device — list devices on your linked AuthPlatform account',
  '/oauth — learn how to approve a device sign-in',
  '',
  'Security: never send passwords, recovery codes, API tokens, or one-time login codes to this bot.',
].join('\\n');

export function parseCommand(text = '') {
  const token = text.trim().split(/\\s+/, 1)[0] ?? '';
  return token.split('@', 1)[0].toLowerCase();
}

function requiredConfig(env) {
  const base = env.AUTHPLATFORM_API_URL?.trim().replace(/\\/+$/, '');
  const secret = env.TELEGRAM_BOT_SHARED_SECRET;
  if (!base || !secret) throw new Error('AuthPlatform integration is not configured');
  const url = new URL(base);
  if (url.protocol !== 'https:') throw new Error('AuthPlatform API URL must use HTTPS');
  return { base, secret };
}

export function createCommandHandler({ env = process.env, fetchImpl = fetch } = {}) {
  async function apiRequest(path, { method = 'GET', body } = {}) {
    const { base, secret } = requiredConfig(env);
    const response = await fetchImpl(new URL(path, base), {
      method,
      headers: {
        'X-AuthPlatform-Telegram-Secret': secret,
        ...(body === undefined ? {} : { 'Content-Type': 'application/json' }),
      },
      ...(body === undefined ? {} : { body: JSON.stringify(body) }),
      signal: AbortSignal.timeout(8000),
    });
    if (!response.ok) throw new Error(`AuthPlatform returned HTTP ${response.status}`);
    return response.status === 204 ? null : response.json();
  }

  return async function handleMessage(message) {
    if (!message?.chat?.id || typeof message.text !== 'string') return null;
    const command = parseCommand(message.text);
    const telegramUserID = message.from?.id == null ? null : String(message.from.id);

    switch (command) {
      case '/start':
        return 'Welcome to AuthPlatform. Use /link to connect this Telegram account, /device to view linked devices, and /help for commands.';
      case '/help':
        return HELP;
      case '/status':
        try {
          const result = await apiRequest('/v1/telegram/status');
          return `AuthPlatform API: ${result.status}\\nService: ${result.service}`;
        } catch {
          return 'AuthPlatform is unavailable or its service credentials are not configured.';
        }
      case '/link':
        if (!telegramUserID) return 'Telegram user identity is unavailable for this message.';
        try {
          const result = await apiRequest('/v1/telegram/link-challenges', {
            method: 'POST',
            body: { telegram_user_id: telegramUserID },
          });
          return [
            'Account-link verification',
            `Your one-time link code is: ${result.code}`,
            '',
            'Sign in to AuthPlatform and enter this code in its Telegram linking screen.',
            'The code expires in 10 minutes. Never share your password or login token with this bot.',
          ].join('\\n');
        } catch {
          return 'Could not create a link code. Check AuthPlatform availability and try again.';
        }
      case '/device':
        if (!telegramUserID) return 'Telegram user identity is unavailable for this message.';
        try {
          const result = await apiRequest(`/v1/telegram/devices?telegram_user_id=${encodeURIComponent(telegramUserID)}`);
          if (!result.devices?.length) return 'No active devices are registered on the linked AuthPlatform account.';
          return [
            'Your active AuthPlatform devices:',
            ...result.devices.map((device, index) =>
              `${index + 1}. ${device.label} — ${device.platform} (ID: ${device.id})`),
          ].join('\\n');
        } catch {
          return 'This Telegram account is not linked, or AuthPlatform is unavailable. Use /link first.';
        }
      case '/oauth':
        return 'To sign in on another device, start the OAuth device authorization flow in that device’s AuthPlatform client. Open the verification URL it displays, sign in with WorkOS, review the request, and approve it. This bot never issues or delivers access tokens.';
      default:
        return 'I did not recognize that command. Use /help. Never send passwords or authentication codes here.';
    }
  };
}
