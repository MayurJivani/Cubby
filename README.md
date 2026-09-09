# Cubby

A drop box for your own devices. Paste text or drop files on the laptop, pick them
up on the phone a second later. Everything is encrypted in the browser before it
leaves, so the server — yours or anyone's — stores bytes it cannot read.

No account, no cloud service, no dependencies. One Node process and about 600
lines.

```bash
npx cubby-drop
```

Open the page, hit **Start a cubby**, and type the pairing code into your other
device. Once.

## Pair once, not every time

The pairing code *is* the cubby:

```
9FSX-5897-7BED-QTEG
```

One PBKDF2 pass over that code produces two things — an AES-GCM key, and the room
id the server files your items under. Same code, same room, same key, on any
device, forever. The server only ever sees the room id, which is a one-way slice
of the same stretched output and tells it nothing about the key.

Both devices save the code in `localStorage`, so after that first time you just
open the page and your stuff is there. There's nothing to scan and nothing to
re-approve — which is also why there's no QR code in this project: 16 characters
from an alphabet with no `I`, `L`, `O`, `U`, `0` or `1` is about 78 bits, and it's
short enough to read off a screen and type with a thumb.

Lose interest in a device? **Forget on this device** clears the code there and
leaves the others alone.

## What the server knows

| it stores | it can read |
|---|---|
| a room id | ✗ derived from a code it never receives |
| a metadata blob | ✗ AES-GCM — this is where the filename and any text live |
| a file blob | ✗ AES-GCM |
| the size and timestamp | ✓ |

That's the whole threat model. It hides content and filenames from whoever runs
the box; it does not hide that a room exists, how big things are, or when you
dropped them. Anyone holding the code can read everything in the room, so treat
the code the way you'd treat the contents.

## HTTPS is not optional

Browsers only hand out `crypto.subtle` in a secure context, and Cubby has no
plaintext mode to fall back to. So it works on `localhost`, and it works on any
`https://` address — but a bare `http://192.168.x.x` LAN address will load and
tell you to use the HTTPS one rather than quietly downgrading. Put it behind the
TLS terminator you already have (see `deploy/`).

## Deploying it

`deploy/` targets the Caddy + systemd setup on Jinx, in the same shape as the
other sites:

```bash
sudo deploy/install.sh   # once: systemd unit + Caddy site block, both replaceable
deploy/deploy.sh         # every time after: tarball, restart, check it came back
```

`cubby.service` runs it as a `DynamicUser` with one writable directory
(`/var/lib/cubby`), a 512 MB memory cap, and no view of the rest of the box.
`cubby.caddy` reverse-proxies with `flush_interval -1`, without which the SSE feed
gets buffered and the other device looks dead.

For anywhere else, there's a `Dockerfile`, and every flag reads from the
environment:

```bash
docker run -p 4747:4747 -v cubby:/data cubby
```

| flag | env | default | |
|---|---|---|---|
| `--port`, `-p` | `PORT` | `4747` | |
| `--dir`, `-d` | `CUBBY_DIR` | `cubby-data` | where ciphertext lands |
| `--pin` | `CUBBY_PIN` | none | gate the whole server, before any room |
| `--hours` | `CUBBY_HOURS` | `24` | how long an item survives |
| `--mb` | `CUBBY_MB` | `512` | total size cap across all rooms |
| `--trust-proxy` | `CUBBY_TRUST_PROXY=1` | off | rate-limit on `X-Forwarded-For`, not the proxy's socket |

On a public deployment, `--pin` decides whether strangers can create rooms in your
server at all. Without it the server is open — rate-limited to 240 requests a
minute per client, capped in size, and self-emptying on a timer, but open.

## What it does

- **Text both ways.** Type or paste, Send (or Ctrl/Cmd+Enter). Tap **Copy** on the
  other device.
- **Files both ways.** Drop them on the page, pick them, or paste an image straight
  from the clipboard. Encrypted client-side, up to 64 MB each.
- **Live.** Items appear on every open device at once over SSE. No refresh.
- **Self-sweeping.** Items expire after `--hours`; the pile is capped per room and
  in total, oldest evicted first. It never quietly fills your disk.

## As a library

```js
import { createServer } from 'cubby-drop';

createServer({ dir: './drops', pin: '1234', trustProxy: true }).listen(4747);
```

Returns a plain `http.Server` with the `Store` on `server.store`. The crypto half
is standalone too — `cubby-drop/crypto` runs unchanged in Node and the browser:

```js
import { newCode, deriveIdentity, sealMeta } from 'cubby-drop/crypto';

const { room, key } = await deriveIdentity(newCode());
```

## HTTP API

Everything is scoped to `?room=`, and `x-meta` is the sealed metadata.

| | |
|---|---|
| `GET /api/items?room=R` | the room, newest first |
| `GET /api/events?room=R` | SSE stream, one frame per change |
| `POST /api/item?room=R` | `x-meta` header; body is the ciphertext, or empty for text-only |
| `GET /api/blob/:id?room=R` | download the ciphertext |
| `DELETE /api/items/:id?room=R` | remove one |
| `DELETE /api/items?room=R` | empty the room |

Which makes another machine's terminal a device too, as long as it can derive the
same room and key — see `src/crypto.js`.

## Tests

```bash
node --test
```

Ten of them, covering the code derivation, that a wrong code opens nothing, that
tampered ciphertext is rejected, that rooms can't reach into each other, that the
plaintext never appears on disk, and the caps, rate limit, and PIN gate.

MIT.
