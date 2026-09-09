// A dumb relay. It files opaque bytes under an opaque room id, hands them back,
// and forgets them on a timer. It cannot read anything it stores — see crypto.js.
import http from 'node:http';
import fs from 'node:fs';
import path from 'node:path';
import { pipeline } from 'node:stream/promises';
import { createHash, randomBytes, timingSafeEqual } from 'node:crypto';
import { fileURLToPath } from 'node:url';
import { Store, ROOM } from './store.js';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const STATIC = {
  '/': ['text/html; charset=utf-8', fs.readFileSync(path.join(HERE, 'index.html'))],
  '/crypto.js': ['text/javascript; charset=utf-8', fs.readFileSync(path.join(HERE, 'crypto.js'))],
  '/app.js': ['text/javascript; charset=utf-8', fs.readFileSync(path.join(HERE, 'app.js'))],
  '/manifest.webmanifest': ['application/manifest+json', fs.readFileSync(path.join(HERE, 'manifest.webmanifest'))],
  '/icon.svg': ['image/svg+xml', fs.readFileSync(path.join(HERE, 'icon.svg'))],
};
const MAX_META = 8 * 1024;

export function createServer({ dir = 'cubby-data', pin = '', trustProxy = false, rate = 240, ...limits } = {}) {
  const store = new Store({ dir, ...limits });
  // Session token derives from the pin plus a per-run secret, so restarting invalidates old cookies.
  const secret = randomBytes(16);
  const token = pin ? createHash('sha256').update(secret).update(pin).digest('hex') : '';

  const clients = new Set();
  store.on('change', (room) => {
    for (const res of clients) if (res.room === room) push(res, store.list(room));
  });

  const buckets = new Map();
  setInterval(() => buckets.clear(), 60_000).unref();

  const server = http.createServer(async (req, res) => {
    const url = new URL(req.url, 'http://localhost');
    const route = `${req.method} ${url.pathname}`;
    // Stored bytes are attacker-supplied and served back to browsers. Nothing
    // here is ever script, so say so and mean it.
    res.setHeader('X-Content-Type-Options', 'nosniff');
    // img-src covers the decrypted previews, which are blob: URLs made in the page.
    res.setHeader('Content-Security-Policy', "default-src 'self'; style-src 'unsafe-inline'; connect-src 'self'; img-src 'self' blob:");
    res.setHeader('Referrer-Policy', 'no-referrer');

    try {
      const asset = STATIC[url.pathname];
      if (asset && req.method === 'GET') return send(res, 200, asset[0], asset[1]);

      if (spend(clientKey(req, trustProxy), buckets, rate)) return json(res, 429, { error: 'slow down' });

      if (route === 'GET /api/auth') return json(res, 200, { needsPin: Boolean(pin), ok: authed(req) });
      if (route === 'POST /api/auth') {
        const given = (await readBody(req, 1024)).toString('utf8').trim();
        if (!pin || !equals(given, pin)) return json(res, 401, { error: 'wrong pin' });
        res.setHeader('Set-Cookie', `cubby=${token}; HttpOnly; SameSite=Strict; Path=/; Max-Age=2592000`);
        return json(res, 200, { ok: true });
      }
      if (!authed(req)) return json(res, 401, { error: 'pin required' });

      // Past this point everything is scoped to a room, and a room id the client
      // did not derive is just a room that happens to be empty.
      const room = url.searchParams.get('room') || '';
      if (!ROOM.test(room)) return json(res, 400, { error: 'bad room' });

      if (route === 'GET /api/items') return json(res, 200, store.list(room));
      if (route === 'GET /api/events') return subscribe(res, room);

      if (route === 'POST /api/item') {
        const meta = String(req.headers['x-meta'] || '');
        if (!meta || meta.length > MAX_META) return json(res, 400, { error: 'bad meta' });
        // A body means there is a blob; text-only items live entirely in meta.
        // Which one this is comes from what actually arrived, not from a
        // Content-Length the sender may never have set.
        const pending = store.begin();
        try {
          const out = fs.createWriteStream(pending.path);
          await pipeline(cap(req, store.maxBytes), out);
          if (out.bytesWritten === 0) {
            store.drop(pending.id);
            return json(res, 200, store.add({ room, id: pending.id, meta }));
          }
          return json(res, 200, store.add({ room, id: pending.id, meta, size: out.bytesWritten, blob: true }));
        } catch (err) {
          store.drop(pending.id);
          throw err;
        }
      }

      const blob = route.match(/^GET \/api\/blob\/([\w-]+)$/);
      if (blob) {
        const item = store.get(blob[1], room);
        if (!item?.blob) return json(res, 404, { error: 'gone' });
        res.writeHead(200, { 'Content-Type': 'application/octet-stream', 'Content-Length': item.size });
        return fs.createReadStream(store.blobPath(item.id)).pipe(res);
      }

      const del = route.match(/^DELETE \/api\/items\/([\w-]+)$/);
      if (del) return json(res, store.remove(del[1], room) ? 200 : 404, { ok: true });
      if (route === 'DELETE /api/items') return (store.clear(room), json(res, 200, { ok: true }));

      return json(res, 404, { error: 'no such thing' });
    } catch (err) {
      if (!res.headersSent) json(res, err.status || 500, { error: err.message });
      else res.destroy();
    }
  });

  function authed(req) {
    if (!pin) return true;
    const cookie = /(?:^|;\s*)cubby=([a-f0-9]+)/.exec(req.headers.cookie || '');
    return Boolean(cookie) && equals(cookie[1], token);
  }

  function subscribe(res, room) {
    res.writeHead(200, { 'Content-Type': 'text/event-stream', 'Cache-Control': 'no-cache', Connection: 'keep-alive' });
    res.room = room;
    push(res, store.list(room));
    clients.add(res);
    res.on('close', () => clients.delete(res));
  }

  server.on('close', () => {
    for (const res of clients) res.end();
    clients.clear();
  });
  server.store = store;
  return server;
}

const push = (res, items) => res.write(`data: ${JSON.stringify(items)}\n\n`);

function send(res, status, type, body) {
  res.writeHead(status, { 'Content-Type': type, 'Content-Length': body.length });
  res.end(body);
}

function json(res, status, body) {
  send(res, status, 'application/json', Buffer.from(JSON.stringify(body)));
}

function equals(a, b) {
  const x = Buffer.from(String(a));
  const y = Buffer.from(String(b));
  return x.length === y.length && timingSafeEqual(x, y);
}

/** Behind a proxy every request shares one socket address; the last hop in XFF is the real client. */
function clientKey(req, trustProxy) {
  const xff = String(req.headers['x-forwarded-for'] || '').split(',').map((s) => s.trim()).filter(Boolean);
  return (trustProxy && xff.at(-1)) || req.socket.remoteAddress || '?';
}

/** Fixed-window counter per client. Returns true when the caller is over budget. */
function spend(key, buckets, rate) {
  const used = (buckets.get(key) || 0) + 1;
  buckets.set(key, used);
  return used > rate;
}

async function readBody(req, limit) {
  const chunks = [];
  let size = 0;
  for await (const chunk of req) {
    size += chunk.length;
    if (size > limit) throw Object.assign(new Error('too big'), { status: 413 });
    chunks.push(chunk);
  }
  return Buffer.concat(chunks);
}

/** Stop a stream that runs past the size cap instead of filling the disk. */
async function* cap(stream, limit) {
  let size = 0;
  for await (const chunk of stream) {
    size += chunk.length;
    if (size > limit) throw Object.assign(new Error('too big'), { status: 413 });
    yield chunk;
  }
}
