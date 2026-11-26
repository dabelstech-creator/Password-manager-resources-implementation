import test from 'node:test';
import assert from 'node:assert/strict';
import { createGatewayServer } from '../src/server.js';

const env = {
  TELEGRAM_BOT_TOKEN: '123:test-token',
  TELEGRAM_WEBHOOK_SECRET: 'a-long-random-webhook-secret',
  AUTHPLATFORM_API_URL: 'https://auth.example.test',
  TELEGRAM_BOT_SHARED_SECRET: 'test-only-api-secret',
};

async function withServer(server, run) {
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  const address = server.address();
  try {
    await run('http://127.0.0.1:' + address.port);
  } finally {
    await new Promise((resolve, reject) => server.close(error => error ? reject(error) : resolve()));
  }
}

test('health endpoint does not require Telegram or AuthPlatform requests', async () => {
  const server = createGatewayServer({ env, fetchImpl: async () => { throw new Error('unexpected fetch'); } });
  await withServer(server, async base => {
    const response = await fetch(base + '/health');
    assert.equal(response.status, 200);
    assert.equal((await response.json()).status, 'ok');
  });
});

test('webhook rejects requests without Telegram secret token', async () => {
  const server = createGatewayServer({ env, fetchImpl: async () => { throw new Error('unexpected fetch'); } });
  await withServer(server, async base => {
    const response = await fetch(base + '/telegram/webhook', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ update_id: 1, message: { chat: { id: 7 }, text: '/help' } }),
    });
    assert.equal(response.status, 401);
  });
});

test('webhook validates secret, sends reply, and de-duplicates update IDs', async () => {
  const calls = [];
  const server = createGatewayServer({
    env,
    fetchImpl: async (url, options) => {
      calls.push({ url: String(url), options });
      return { ok: true, status: 200, json: async () => ({ ok: true }) };
    },
  });
  await withServer(server, async base => {
    const payload = { update_id: 42, message: { chat: { id: 7 }, from: { id: 9 }, text: '/help' } };
    const request = () => fetch(base + '/telegram/webhook', {
      method: 'POST',
      headers: {
        'content-type': 'application/json',
        'x-telegram-bot-api-secret-token': env.TELEGRAM_WEBHOOK_SECRET,
      },
      body: JSON.stringify(payload),
    });
    assert.equal((await request()).status, 200);
    const duplicate = await request();
    assert.equal(duplicate.status, 200);
    assert.equal((await duplicate.json()).duplicate, true);
    assert.equal(calls.length, 1);
    assert.match(calls[0].url, /api\.telegram\.org\/bot123:test-token\/sendMessage$/);
    assert.equal(JSON.parse(calls[0].options.body).chat_id, 7);
  });
});
