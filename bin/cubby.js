#!/usr/bin/env node
import os from 'node:os';
import { parseArgs } from 'node:util';
import { createServer } from '../src/server.js';

const env = process.env;
const { values } = parseArgs({
  options: {
    port: { type: 'string', short: 'p', default: env.PORT || '4747' },
    dir: { type: 'string', short: 'd', default: env.CUBBY_DIR || 'cubby-data' },
    pin: { type: 'string', default: env.CUBBY_PIN || '' },
    hours: { type: 'string', default: env.CUBBY_HOURS || '24' },
    mb: { type: 'string', default: env.CUBBY_MB || '512' },
    'max-item-mb': { type: 'string', default: env.CUBBY_MAX_ITEM_MB || '80' },
    'admin-key': { type: 'string', default: env.CUBBY_ADMIN_KEY || '' },
    'max-keep-hours': { type: 'string', default: env.CUBBY_MAX_KEEP_HOURS || '168' },
    'trust-proxy': { type: 'boolean', default: env.CUBBY_TRUST_PROXY === '1' },
    help: { type: 'boolean', short: 'h' },
  },
});

if (values.help) {
  console.log(`cubby — an end-to-end encrypted drop box for your own devices

  cubby [--port 4747] [--dir cubby-data] [--pin 1234] [--hours 24] [--mb 512] [--max-item-mb 80] [--admin-key KEY] [--trust-proxy]

Open the printed URL, start a cubby, and type the pairing code into your other
device once. The server stores ciphertext only; the code never reaches it.
Every flag also reads from the environment: PORT, CUBBY_DIR, CUBBY_PIN,
CUBBY_HOURS, CUBBY_MB, CUBBY_MAX_ITEM_MB, CUBBY_ADMIN_KEY,
CUBBY_MAX_KEEP_HOURS, CUBBY_TRUST_PROXY=1.`);
  process.exit(0);
}

const server = createServer({
  dir: values.dir,
  pin: values.pin,
  trustProxy: values['trust-proxy'],
  ttlMs: Number(values.hours) * 3600_000,
  maxBytes: Number(values.mb) * 1024 * 1024,
  maxItemBytes: Number(values['max-item-mb']) * 1024 * 1024,
  adminKey: values['admin-key'],
  maxTtlMs: Number(values['max-keep-hours']) * 3600_000,
});

server.listen(Number(values.port), '0.0.0.0', () => {
  const urls = Object.values(os.networkInterfaces())
    .flat()
    .filter((i) => i.family === 'IPv4' && !i.internal)
    .map((i) => `http://${i.address}:${values.port}`);

  console.log(`\n  cubby is open at http://localhost:${values.port}`);
  for (const url of urls) console.log(`  on this network: ${url}`);
  // WebCrypto is only handed out in a secure context, and cubby has no
  // plaintext mode, so a bare LAN address will refuse to work in the browser.
  if (urls.length) console.log('\n  Those plain-http addresses need a TLS terminator in front — see deploy/.');
  if (!values.pin) console.log('  No PIN: anyone who can reach this server can create rooms in it. --pin gates that.');
  console.log('');
});

for (const signal of ['SIGINT', 'SIGTERM']) {
  process.on(signal, () => server.close(() => process.exit(0)));
}
