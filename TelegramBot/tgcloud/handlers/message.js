import { api } from 'sdk';

const HELP = [
  'AuthPlatform — @moredesaBot',
  '',
  'Commands:',
  '/start — introduction',
  '/help — show commands',
  '/status — integration readiness',
  '/device — device-binding status',
  '/oauth — OAuth device authorization status',
  '',
  'Security: never send passwords, recovery codes, API tokens, or one-time codes to this bot.',
].join('\n');

function responseFor(text) {
  const command = (text ?? '').trim().split(/\s+/, 1)[0].split('@')[0].toLowerCase();

  switch (command) {
    case '/start':
      return 'Welcome to AuthPlatform. This bot is the Telegram interface for the AuthPlatform prototype. Use /help to see available commands.';
    case '/help':
      return HELP;
    case '/status':
      return [
        'AuthPlatform integration status',
        'Telegram Serverless handler: configured in source',
        'AuthPlatform API connection: not configured',
        'Device binding: not implemented in the current API',
        'OAuth device authorization: not implemented in the current API',
        '',
        'No authentication decision or credential verification is performed by this bot yet.',
      ].join('\n');
    case '/device':
      return 'Device binding is not yet available. The current AuthPlatform service exposes a prototype decision endpoint only; it does not register, bind, revoke, or verify devices.';
    case '/oauth':
      return 'OAuth device authorization is not yet available. The current repository does not expose device-code issuance, polling, token exchange, or token validation endpoints.';
    default:
      return 'I did not recognize that command. Use /help. Do not send passwords or authentication codes here.';
  }
}

export default async function (message) {
  if (!message?.chat?.id || typeof message.text !== 'string') return;

  await api.sendMessage({
    chat_id: message.chat.id,
    text: responseFor(message.text),
  });
}
