import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { Store } from '../src/store.js';
import { createServer } from '../src/server.js';
import { newCode, normalize, format, deriveIdentity, encrypt, decrypt, sealMeta, openMeta } from '../src/crypto.js';

const tmp = () => fs.mkdtempSync(path.join(os.tmpdir(), 'cubby-'));
const ROOM = 'test-room-1';

test('a pairing code is typeable and forgiving', () => {
  const code = newCode();
  assert.match(code, /^[2-9A-Z]{4}-[2-9A-Z]{4}-[2-9A-Z]{4}-[2-9A-Z]{4}$/);
  assert.ok(!/[ILOU01]/.test(code), 'no lookalike characters');
  assert.equal(normalize(' abcd efgh '), normalize('ABCD-EFGH'));
  assert.equal(format(normalize('abcdefgh')), 'ABCD-EFGH');
});

test('the same code derives the same room and key, a different one does not', async () => {
  const a = await deriveIdentity('ABCD-EFGH-JKMN-PQRS');
  const b = await deriveIdentity('abcdefghjkmnpqrs');
  const c = await deriveIdentity('ABCD-EFGH-JKMN-PQRT');

  assert.equal(a.room, b.room, 'formatting and case must not matter');
  assert.notEqual(a.room, c.room);
  assert.match(a.room, /^[A-Za-z0-9_-]{4,64}$/);

  const sealed = await sealMeta(a.key, { kind: 'text', text: 'hello phone' });
  assert.deepEqual(await openMeta(b.key, sealed), { kind: 'text', text: 'hello phone' });
  await assert.rejects(openMeta(c.key, sealed), 'the wrong code must not open it');
});

test('ciphertext carries its own iv and detects tampering', async () => {
  const { key } = await deriveIdentity(newCode());
  const sealed = await encrypt(key, new TextEncoder().encode('payload'));
  assert.equal(new TextDecoder().decode(await decrypt(key, sealed)), 'payload');
  assert.ok(!Buffer.from(sealed).includes('payload'), 'plaintext must not survive');

  sealed[sealed.length - 1] ^= 1;
  await assert.rejects(decrypt(key, sealed));
});

test('store evicts by room count, total size and age', () => {
  const store = new Store({ dir: tmp(), maxItems: 3, ttlMs: 50 });
  for (const meta of ['a', 'b', 'c', 'd']) store.add({ room: ROOM, meta });
  store.add({ room: 'other', meta: 'e' });
  assert.deepEqual(store.list(ROOM).map((i) => i.meta), ['d', 'c', 'b'], 'per-room cap');
  assert.equal(store.list('other').length, 1, 'rooms do not evict each other');

  const small = new Store({ dir: tmp(), maxBytes: 10 });
  small.add({ room: ROOM, meta: 'x', size: 8 });
  small.add({ room: ROOM, meta: 'y', size: 8 });
  assert.deepEqual(small.list(ROOM).map((i) => i.meta), ['y']);

  store.items.find((i) => i.meta === 'd').at -= 1000;
  assert.equal(store.list(ROOM).length, 2, 'expired items go');
});

test('store survives a restart and forgets vanished blobs', () => {
  const dir = tmp();
  const store = new Store({ dir });
  const kept = store.add({ room: ROOM, meta: 'still here' });
  store.add({ room: ROOM, meta: 'gone', size: 4, blob: true });
  assert.deepEqual(new Store({ dir }).list(ROOM).map((i) => i.id), [kept.id]);
});

async function serve(opts) {
  const server = createServer({ dir: tmp(), ...opts });
  await new Promise((r) => server.listen(0, '127.0.0.1', r));
  return {
    base: `http://127.0.0.1:${server.address().port}`,
    server,
    done: () => new Promise((r) => server.close(r)),
  };
}

test('an item round-trips through the server without it learning anything', async () => {
  const { base, server, done } = await serve();
  const { room, key } = await deriveIdentity(newCode());
  try {
    const body = await encrypt(key, new TextEncoder().encode('the secret plans'));
    const post = await fetch(`${base}/api/item?room=${room}`, {
      method: 'POST',
      headers: { 'x-meta': await sealMeta(key, { kind: 'file', name: 'plans.txt', type: 'text/plain' }) },
      body,
    });
    assert.equal(post.status, 200);

    const items = await (await fetch(`${base}/api/items?room=${room}`)).json();
    assert.equal(items.length, 1);
    assert.deepEqual(Object.keys(items[0]).sort(), ['at', 'blob', 'id', 'meta', 'room', 'size'].sort());
    assert.deepEqual(await openMeta(key, items[0].meta), { kind: 'file', name: 'plans.txt', type: 'text/plain' });

    // What the operator can see on disk: no filename, no contents.
    const onDisk = fs.readFileSync(path.join(server.store.blobPath(items[0].id)));
    assert.ok(!onDisk.includes('secret plans') && !onDisk.includes('plans.txt'));
    assert.ok(!fs.readFileSync(path.join(server.store.dir, 'index.json'), 'utf8').includes('plans.txt'));

    const fetched = await fetch(`${base}/api/blob/${items[0].id}?room=${room}`);
    const opened = await decrypt(key, await fetched.arrayBuffer());
    assert.equal(new TextDecoder().decode(opened), 'the secret plans');
  } finally {
    await done();
  }
});

test('a text item leaves no blob behind, however it was sent', async () => {
  const { base, server, done } = await serve();
  const { room, key } = await deriveIdentity(newCode());
  const meta = await sealMeta(key, { kind: 'text', text: 'no body here' });
  try {
    // An empty body, and no body at all — curl sends the second one.
    await fetch(`${base}/api/item?room=${room}`, { method: 'POST', headers: { 'x-meta': meta }, body: new Uint8Array() });
    await fetch(`${base}/api/item?room=${room}`, { method: 'POST', headers: { 'x-meta': meta } });

    const items = await (await fetch(`${base}/api/items?room=${room}`)).json();
    assert.equal(items.length, 2);
    assert.deepEqual(items.map((i) => i.blob), [false, false]);
    assert.deepEqual(fs.readdirSync(server.store.blobs), [], 'no empty blob files');
  } finally {
    await done();
  }
});

test('rooms are sealed off from each other', async () => {
  const { base, done } = await serve();
  const mine = await deriveIdentity(newCode());
  const yours = await deriveIdentity(newCode());
  try {
    const post = await fetch(`${base}/api/item?room=${mine.room}`, {
      method: 'POST',
      headers: { 'x-meta': await sealMeta(mine.key, { kind: 'text', text: 'mine' }) },
    });
    const { id } = await post.json();

    assert.deepEqual(await (await fetch(`${base}/api/items?room=${yours.room}`)).json(), []);
    assert.equal((await fetch(`${base}/api/blob/${id}?room=${yours.room}`)).status, 404);
    assert.equal((await fetch(`${base}/api/items/${id}?room=${yours.room}`, { method: 'DELETE' })).status, 404);
    assert.equal((await fetch(`${base}/api/items?room=nope!`)).status, 400);

    assert.equal((await (await fetch(`${base}/api/items?room=${mine.room}`)).json()).length, 1, 'still there');
  } finally {
    await done();
  }
});

test('oversized uploads are refused, not written', async () => {
  const { base, server, done } = await serve({ maxBytes: 16 });
  const { room, key } = await deriveIdentity(newCode());
  try {
    const res = await fetch(`${base}/api/item?room=${room}`, {
      method: 'POST',
      headers: { 'x-meta': await sealMeta(key, { kind: 'file', name: 'big.bin' }) },
      body: Buffer.alloc(64),
    });
    assert.equal(res.status, 413);
    assert.equal(server.store.list(room).length, 0);
    assert.deepEqual(fs.readdirSync(server.store.blobs), [], 'no half-written blob left behind');
  } finally {
    await done();
  }
});

test('a flood of requests gets cut off', async () => {
  const { base, done } = await serve({ rate: 5 });
  const { room } = await deriveIdentity(newCode());
  try {
    const codes = [];
    for (let i = 0; i < 8; i++) codes.push((await fetch(`${base}/api/items?room=${room}`)).status);
    assert.ok(codes.includes(429), `expected a 429, got ${codes.join(',')}`);
    assert.equal(codes[0], 200, 'the first ones go through');
  } finally {
    await done();
  }
});

test('a pin gates the whole server until you give it', async () => {
  const { base, done } = await serve({ pin: '1234' });
  const { room } = await deriveIdentity(newCode());
  try {
    assert.equal((await fetch(`${base}/api/items?room=${room}`)).status, 401);
    assert.equal((await fetch(`${base}/api/auth`, { method: 'POST', body: '9999' })).status, 401);

    const ok = await fetch(`${base}/api/auth`, { method: 'POST', body: '1234' });
    const cookie = ok.headers.getSetCookie()[0].split(';')[0];
    assert.equal((await fetch(`${base}/api/items?room=${room}`, { headers: { cookie } })).status, 200);
  } finally {
    await done();
  }
});
