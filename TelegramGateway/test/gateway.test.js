import test from 'node:test';
import assert from 'node:assert/strict';
import { createCommandHandler, parseCommand } from '../src/gateway.js';

const env = {
  AUTHPLATFORM_API_URL: 'https://auth.example.test',
  TELEGRAM_BOT_SHARED_SECRET: 'test-only-secret',
};

test('parses commands with bot suffix and arguments', () => {
  assert.equal(parseCommand('/status@moredesaBot'), '/status');
  assert.equal(parseCommand('/link extra'), '/link');
  assert.equal(parseCommand('hello'), 'hello');
});

test('/help is local and does not call external APIs', async () => {
  let calls = 0;
  const handle = createCommandHandler({ env, fetchImpl: async () => { calls++; throw new Error('unexpected'); } });
  const reply = await handle({ chat: { id: 1 }, from: { id: 2 }, text: '/help' });
  assert.match(reply, /\/status/);
  assert.equal(calls, 0);
});

test('/status authenticates to AuthPlatform', async () => {
  let request;
  const handle = createCommandHandler({
    env,
    fetchImpl: async (url, options) => {
      request = { url: String(url), options };
      return { ok: true, status: 200, json: async () => ({ status: 'ready', service: 'AuthPlatform' }) };
    },
  });
  assert.equal(await handle({ chat: { id: 1 }, from: { id: 2 }, text: '/status' }),
    'AuthPlatform API: ready\nService: AuthPlatform');
  assert.equal(request.url, 'https://auth.example.test/v1/telegram/status');
  assert.equal(request.options.headers['X-AuthPlatform-Telegram-Secret'], 'test-only-secret');
});

test('/link sends only the Telegram user ID to AuthPlatform', async () => {
  let payload;
  const handle = createCommandHandler({
    env,
    fetchImpl: async (_url, options) => {
      payload = JSON.parse(options.body);
      return { ok: true, status: 200, json: async () => ({ code: 'ABCD2345', expires_in: 600 }) };
    },
  });
  const reply = await handle({ chat: { id: 1 }, from: { id: 987654 }, text: '/link' });
  assert.deepEqual(payload, { telegram_user_id: '987654' });
  assert.match(reply, /ABCD2345/);
});

test('rejects non-HTTPS AuthPlatform URLs', async () => {
  const handle = createCommandHandler({
    env: { ...env, AUTHPLATFORM_API_URL: 'http://auth.example.test' },
    fetchImpl: async () => { throw new Error('must not call'); },
  });
  assert.match(await handle({ chat: { id: 1 }, from: { id: 2 }, text: '/status' }), /unavailable/);
});
