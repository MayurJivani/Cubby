import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { Store } from '../src/store.js';
import { createServer } from '../src/server.js';
import { newCode, normalize, format, deriveIdentity, encrypt, decrypt, sealMeta, openMeta, newShareKey, fingerprint } from '../src/crypto.js';

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

test('the sender picks how long a drop lives, the server holds the ceiling', async () => {
  const { base, server, done } = await serve({ maxTtlMs: 7200_000 }); // two hours, no more
  const { room, key } = await deriveIdentity(newCode());
  const meta = await sealMeta(key, { kind: 'text', text: 'briefly' });
  try {
    const put = async (seconds) => (await (await fetch(`${base}/api/item?room=${room}`, {
      method: 'POST',
      headers: seconds === null ? { 'x-meta': meta } : { 'x-meta': meta, 'x-keep': String(seconds) },
    })).json());

    const short = await put(7200 / 2);
    const greedy = await put(604_800); // a week, from a server that allows two hours
    const silent = await put(null);

    assert.ok(short.expiresAt - Date.now() <= 3600_000 + 2000, 'an hour stays an hour');
    assert.ok(greedy.expiresAt - Date.now() <= 7200_000 + 2000, 'clamped to the ceiling');
    assert.equal(silent.expiresAt, undefined, 'no header means the store default');

    // Wind one past its deadline and it goes, while its neighbours stay.
    server.store.items.find((i) => i.id === short.id).expiresAt = Date.now() - 1;
    const left = server.store.list(room).map((i) => i.id);
    assert.ok(!left.includes(short.id));
    assert.deepEqual(left.sort(), [greedy.id, silent.id].sort());
  } finally {
    await done();
  }
});

test('a sign-in lasts as long as it was asked to, and survives a restart', async () => {
  const dir = tmp();
  const first = createServer({ dir, pin: 'open-sesame' });
  await new Promise((r) => first.listen(0, '127.0.0.1', r));
  const base = `http://127.0.0.1:${first.address().port}`;
  const { room } = await deriveIdentity(newCode());

  try {
    const res = await fetch(`${base}/api/auth`, {
      method: 'POST',
      headers: { 'x-session-ttl': '7200' },
      body: 'open-sesame',
    });
    const setCookie = res.headers.getSetCookie()[0];
    assert.match(setCookie, /Max-Age=7200/);
    assert.match(setCookie, /HttpOnly/);
    assert.match(setCookie, /SameSite=Strict/);
    assert.equal((await res.json()).seconds, 7200);

    const cookie = setCookie.split(';')[0];
    assert.equal((await fetch(`${base}/api/items?room=${room}`, { headers: { cookie } })).status, 200);

    // The secret lives next to the data, so the same cookie still works after a
    // redeploy — the whole point of not keeping it in memory.
    await new Promise((r) => first.close(r));
    const second = createServer({ dir, pin: 'open-sesame' });
    await new Promise((r) => second.listen(0, '127.0.0.1', r));
    const again = `http://127.0.0.1:${second.address().port}`;
    assert.equal((await fetch(`${again}/api/items?room=${room}`, { headers: { cookie } })).status, 200);

    assert.match(fs.statSync(path.join(dir, 'secret')).mode.toString(8), /600$/);
    await new Promise((r) => second.close(r));
  } finally {
    if (first.listening) await new Promise((r) => first.close(r));
  }
});

test('guessing at passwords and share tokens runs out of road fast', async () => {
  const { base, done } = await serve({ pin: 'right' });
  try {
    const tries = [];
    for (let i = 0; i < 20; i++) {
      tries.push((await fetch(`${base}/api/auth`, { method: 'POST', body: `wrong-${i}` })).status);
    }
    assert.ok(tries.includes(429), 'the password door closes');
    assert.ok(tries.filter((s) => s === 401).length <= 12, 'and not after many tries');
  } finally {
    await done();
  }
});

test('the response headers lock the page down', async () => {
  const { base, done } = await serve();
  try {
    const res = await fetch(`${base}/`);
    const csp = res.headers.get('content-security-policy');
    for (const directive of ["default-src 'self'", "style-src 'self'", "script-src 'self'", "object-src 'none'", "frame-ancestors 'none'", "form-action 'none'", "base-uri 'none'"]) {
      assert.ok(csp.includes(directive), `CSP is missing ${directive}`);
    }
    assert.equal(res.headers.get('x-frame-options'), 'DENY');
    assert.equal(res.headers.get('referrer-policy'), 'no-referrer');
    assert.equal(res.headers.get('cross-origin-opener-policy'), 'same-origin');
    assert.equal(res.headers.get('x-content-type-options'), 'nosniff');
    assert.equal((await fetch(`${base}/api/auth`)).headers.get('cache-control'), 'no-store');

    // The markup must not need the inline allowances the policy refuses.
    const page = await (await fetch(`${base}/`)).text();
    assert.ok(!/<style[\s>]/.test(page) && !/\sstyle="/.test(page), 'no inline styles to be blocked');
    assert.ok(!/<script(?![^>]*\ssrc=)/.test(page), 'no inline scripts to be blocked');
  } finally {
    await done();
  }
});

/** A minimal SSE reader — enough to watch one room the way a device does. */
async function watch(base, room) {
  const res = await fetch(`${base}/api/events?room=${room}`);
  const reader = res.body.getReader();
  const decoder = new TextDecoder();
  let buffer = '';
  return {
    async frame() {
      for (;;) {
        const end = buffer.indexOf('\n\n');
        if (end !== -1) {
          const frame = buffer.slice(0, end);
          buffer = buffer.slice(end + 2);
          return JSON.parse(frame.replace(/^data: /, ''));
        }
        const { value, done } = await reader.read();
        if (done) throw new Error('stream closed');
        buffer += decoder.decode(value, { stream: true });
      }
    },
    close: () => reader.cancel().catch(() => {}),
  };
}

test('every device on the code sees the same cubby, not just two', async () => {
  const { base, done } = await serve();
  const { room, key } = await deriveIdentity(newCode());
  // A laptop, a phone, a tablet, and a second browser on the laptop.
  const devices = await Promise.all([watch(base, room), watch(base, room), watch(base, room), watch(base, room)]);
  const stranger = await watch(base, (await deriveIdentity(newCode())).room);

  try {
    await Promise.all(devices.map((d) => d.frame())); // the opening frame each gets
    await stranger.frame();

    // A fifth device — the terminal — drops something in.
    await fetch(`${base}/api/item?room=${room}`, {
      method: 'POST',
      headers: { 'x-meta': await sealMeta(key, { kind: 'text', text: 'everyone gets this' }) },
    });

    const seen = await Promise.all(devices.map((d) => d.frame()));
    for (const items of seen) {
      assert.equal(items.length, 1);
      assert.deepEqual(await openMeta(key, items[0].meta), { kind: 'text', text: 'everyone gets this' });
    }
    assert.equal(new Set(seen.map((s) => s[0].id)).size, 1, 'the same item, not four copies');

    // The one watching a different room hears nothing. Give it room to be wrong.
    const quiet = await Promise.race([
      stranger.frame().then(() => 'woke up'),
      new Promise((r) => setTimeout(() => r('stayed quiet'), 300)),
    ]);
    assert.equal(quiet, 'stayed quiet');
  } finally {
    for (const d of [...devices, stranger]) d.close();
    await done();
  }
});

test('share creation, one-time burn-after-read, and crawler protection', async () => {
  const { base, done } = await serve();
  const shareKey = await newShareKey();
  const meta = await sealMeta(shareKey, { kind: 'text', text: 'shared secret' });

  try {
    const shareRes = await fetch(`${base}/api/share`, {
      method: 'POST',
      headers: { 'x-meta': meta, 'x-share-once': '1' },
      body: new Uint8Array(),
    });
    assert.equal(shareRes.status, 200);
    const { token, once } = await shareRes.json();
    assert.equal(once, true);
    assert.ok(token);

    const htmlRes = await fetch(`${base}/s/${token}`);
    assert.equal(htmlRes.status, 200);
    assert.match(await htmlRes.text(), /<title>Shared with you · Cubby<\/title>/);

    const openRes = await fetch(`${base}/api/share/${token}`, { method: 'POST' });
    assert.equal(openRes.status, 200);
    assert.equal(openRes.headers.get('x-once'), '1');
    assert.equal(openRes.headers.get('x-meta'), meta);

    const secondRes = await fetch(`${base}/api/share/${token}`, { method: 'POST' });
    assert.equal(secondRes.status, 404);
  } finally {
    await done();
  }
});

test('one pairing code is the superuser, and the server never learns it', async () => {
  const boss = await deriveIdentity(newCode());
  const anyone = await deriveIdentity(newCode());
  const adminProof = await fingerprint(boss.proof);
  const { base, server, done } = await serve({ maxItemBytes: 32, maxBytes: 4096, maxTtlMs: 3600_000, rate: 4, adminProof });

  try {
    // The server holds a hash, not the code and not the proof.
    assert.equal(adminProof.length, 64);
    assert.notEqual(adminProof, boss.proof);

    const payload = Buffer.alloc(64);
    const send = (who, extra) => fetch(`${base}/api/item?room=${who.room}`, {
      method: 'POST',
      headers: { 'x-meta': 'c2VhbGVk', ...extra },
      body: payload,
    });

    // Over the per-file cap: refused for anyone, fine for the boss.
    assert.equal((await send(anyone, { 'x-proof': anyone.proof })).status, 413);
    assert.equal((await send(boss, { 'x-proof': boss.proof })).status, 200);
    assert.equal(server.store.list(boss.room).length, 1);

    // A made-up proof is just not the superuser.
    assert.equal((await send(anyone, { 'x-proof': 'not-the-proof' })).status, 413);

    // Keep forever: the boss may, anyone else is clamped to the ceiling.
    const kept = await (await fetch(`${base}/api/item?room=${boss.room}`, {
      method: 'POST', headers: { 'x-meta': 'c2VhbGVk', 'x-keep': '0', 'x-proof': boss.proof },
    })).json();
    assert.equal(kept.expiresAt, 0, 'no deadline at all');

    const clamped = await (await fetch(`${base}/api/item?room=${anyone.room}`, {
      method: 'POST', headers: { 'x-meta': 'c2VhbGVk', 'x-keep': '0', 'x-proof': anyone.proof },
    })).json();
    assert.ok(clamped.expiresAt > Date.now(), 'everyone else still gets a deadline');
    assert.ok(clamped.expiresAt - Date.now() <= 3600_000 + 2000);

    // An item with no deadline survives a prune that clears the rest.
    server.store.items.filter((i) => i.expiresAt !== 0).forEach((i) => { i.expiresAt = Date.now() - 1; });
    assert.deepEqual(server.store.list(boss.room).map((i) => i.id), [kept.id]);

    // And the rate limiter does not apply to the boss.
    const mine = [];
    const theirs = [];
    for (let i = 0; i < 8; i++) {
      mine.push((await fetch(`${base}/api/me`, { headers: { 'x-proof': boss.proof } })).status);
      theirs.push((await fetch(`${base}/api/me`, { headers: { 'x-proof': anyone.proof } })).status);
    }
    assert.ok(!mine.includes(429), 'the superuser is never throttled');
    assert.ok(theirs.includes(429), 'everyone else is');
  } finally {
    await done();
  }
});

test('/api/me tells a device what it may do', async () => {
  const boss = await deriveIdentity(newCode());
  const { base, done } = await serve({ maxItemBytes: 1024, maxTtlMs: 7200_000, adminProof: await fingerprint(boss.proof) });
  try {
    const plain = await (await fetch(`${base}/api/me`)).json();
    assert.deepEqual(plain, { admin: false, maxItemBytes: 1024, maxKeepSeconds: 7200 });

    const mine = await (await fetch(`${base}/api/me`, { headers: { 'x-proof': boss.proof } })).json();
    assert.equal(mine.admin, true);
    assert.equal(mine.maxKeepSeconds, 0, 'no ceiling');
    assert.ok(mine.maxItemBytes > 1024);
    assert.equal(typeof mine.rooms, 'number', 'and a look at the server');
  } finally {
    await done();
  }
});

test('default store TTL is 24 hours', () => {
  const store = new Store({ dir: tmp() });
  assert.equal(store.ttlMs, 24 * 60 * 60 * 1000);
});

