import { createServer } from 'node:http';
import { timingSafeEqual } from 'node:crypto';
import { createCommandHandler } from './gateway.js';

const MAX_BODY_BYTES = 64 * 1024;

function safeEqual(left, right) {
  if (typeof left !== 'string' || typeof right !== 'string') return false;
  const a = Buffer.from(left);
  const b = Buffer.from(right);
  return a.length === b.length && timingSafeEqual(a, b);
}

async function readJson(req) {
  let size = 0;
  const chunks = [];
  for await (const chunk of req) {
    size += chunk.length;
    if (size > MAX_BODY_BYTES) throw new Error('Payload too large');
    chunks.push(chunk);
  }
  return JSON.parse(Buffer.concat(chunks).toString('utf8'));
}

function json(res, status, value) {
  res.writeHead(status, { 'content-type': 'application/json; charset=utf-8', 'cache-control': 'no-store' });
  res.end(JSON.stringify(value));
}

export function createGatewayServer({ env = process.env, fetchImpl = fetch } = {}) {
  const botToken = env.TELEGRAM_BOT_TOKEN;
  const webhookSecret = env.TELEGRAM_WEBHOOK_SECRET;
  if (!botToken || !webhookSecret || webhookSecret.length < 16) {
    throw new Error('TELEGRAM_BOT_TOKEN and a 16+ character TELEGRAM_WEBHOOK_SECRET are required');
  }

  const handleMessage = createCommandHandler({ env, fetchImpl });
  const processedUpdates = new Set();

  async function sendMessage(chatID, text) {
    const response = await fetchImpl(`https://api.telegram.org/bot${botToken}/sendMessage`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ chat_id: chatID, text }),
      signal: AbortSignal.timeout(8000),
    });
    if (!response.ok) throw new Error(`Telegram API returned HTTP ${response.status}`);
    const result = await response.json();
    if (!result.ok) throw new Error('Telegram sendMessage failed');
  }

  return createServer(async (req, res) => {
    if (req.method === 'GET' && req.url === '/health') {
      return json(res, 200, { status: 'ok', service: 'AuthPlatform Telegram Gateway' });
    }
    if (req.method !== 'POST' || req.url !== '/telegram/webhook') {
      return json(res, 404, { error: 'not_found' });
    }
    if (!safeEqual(req.headers['x-telegram-bot-api-secret-token'], webhookSecret)) {
      return json(res, 401, { error: 'unauthorized' });
    }

    try {
      const update = await readJson(req);
      if (!Number.isSafeInteger(update.update_id)) return json(res, 400, { error: 'invalid_update' });
      if (processedUpdates.has(update.update_id)) return json(res, 200, { ok: true, duplicate: true });
      const message = update.message;
      if (message?.chat?.id && typeof message.text === 'string') {
        const reply = await handleMessage(message);
        if (reply) await sendMessage(message.chat.id, reply);
      }
      processedUpdates.add(update.update_id);
      if (processedUpdates.size > 10000) processedUpdates.delete(processedUpdates.values().next().value);
      return json(res, 200, { ok: true });
    } catch {
      return json(res, 500, { error: 'processing_failed' });
    }
  });
}

if (import.meta.url === new URL(`file://${process.argv[1]}`).href) {
  const server = createGatewayServer();
  const port = Number(process.env.PORT || 10000);
  server.listen(port, '0.0.0.0', () => {
    // Do not log secrets, request bodies, or Telegram user data.
    console.log(`Telegram Gateway listening on port ${port}`);
  });
}
