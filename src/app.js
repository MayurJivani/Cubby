// The client. Everything that touches plaintext lives on this side of the wire.
import { newCode, format, normalize, deriveIdentity, encrypt, decrypt, sealMeta, openMeta } from './crypto.js';

// ponytail: files are encrypted in one shot, so a file has to fit in memory
// twice. Fine for the phone-to-laptop things this is for; the upgrade path is
// chunked AES-GCM with a per-chunk counter and a streaming reader.
const MAX_FILE = 64 * 1024 * 1024;
const SAVED = 'cubby.code';
const OVERHEAD = 12 + 16; // iv + GCM tag, the difference between file size and stored size

const $ = (id) => document.getElementById(id);
const api = (path, init) => fetch(path, { credentials: 'same-origin', ...init });

// Big enough for a photo off a phone, small enough not to pull a video down by
// accident every time the list re-renders.
const MAX_PREVIEW = 8 * 1024 * 1024;

let key;
let room;
const plaintext = new Map(); // item id -> decrypted meta, so re-renders are free
const previews = new Map(); // item id -> object URL, so an image is fetched once
const fetching = new Set();

function toast(msg) {
  const b = document.createElement('b');
  b.textContent = msg;
  $('status').replaceChildren(b);
  setTimeout(() => b.remove(), 2600);
}

const bytes = (n) =>
  n < 1024 ? `${n} B` : n < 1048576 ? `${(n / 1024).toFixed(0)} KB` : `${(n / 1048576).toFixed(1)} MB`;

const ago = (t) => {
  const s = (Date.now() - t) / 1000;
  if (s < 60) return 'just now';
  if (s < 3600) return `${Math.floor(s / 60)}m ago`;
  if (s < 86400) return `${Math.floor(s / 3600)}h ago`;
  return new Date(t).toLocaleDateString();
};

async function metaOf(item) {
  if (!plaintext.has(item.id)) {
    try {
      plaintext.set(item.id, await openMeta(key, item.meta));
    } catch {
      // Wrong key for this item: someone else's code collided into the room, or
      // the item predates a code change. Show it as undecryptable, keep going.
      plaintext.set(item.id, null);
    }
  }
  return plaintext.get(item.id);
}

/** Pull a blob down and decrypt it, once per item however often we re-render. */
async function objectUrl(item, meta) {
  if (previews.has(item.id)) return previews.get(item.id);
  const res = await api(`/api/blob/${item.id}?room=${room}`);
  const url = URL.createObjectURL(new Blob([await decrypt(key, await res.arrayBuffer())], { type: meta.type }));
  previews.set(item.id, url);
  return url;
}

async function download(item, meta) {
  toast(`Fetching ${meta.name}…`);
  const a = document.createElement('a');
  a.href = await objectUrl(item, meta);
  a.download = meta.name;
  a.click();
}

async function showImage(item, meta, img) {
  if (fetching.has(item.id)) return;
  fetching.add(item.id);
  try {
    img.src = await objectUrl(item, meta);
  } catch {
    img.remove(); // the Download button is still there; a broken preview helps nobody
  } finally {
    fetching.delete(item.id);
  }
}

/** Items that fell off the list take their decrypted copies with them. */
function forget(live) {
  for (const [id, url] of previews) {
    if (live.has(id)) continue;
    URL.revokeObjectURL(url);
    previews.delete(id);
  }
  for (const id of plaintext.keys()) if (!live.has(id)) plaintext.delete(id);
}

async function render(items) {
  const metas = await Promise.all(items.map(metaOf));
  forget(new Set(items.map((i) => i.id)));
  $('count').textContent = items.length ? `${items.length} item${items.length > 1 ? 's' : ''}` : '';
  $('empty').hidden = items.length > 0;

  $('list').replaceChildren(...items.map((item, i) => {
    const meta = metas[i];
    const li = document.createElement('li');
    const bar = document.createElement('div');
    bar.className = 'meta';

    const label = document.createElement('span');
    label.className = 'grow';
    const what = !meta ? "can't decrypt" : meta.kind === 'file' ? meta.name : 'text';
    // item.size is the ciphertext on the server; show what the file actually is.
    const plainSize = item.blob ? item.size - OVERHEAD : new Blob([meta?.text ?? '']).size;
    label.textContent = `${what} · ${bytes(Math.max(plainSize, 0))} · ${ago(item.at)}`;
    bar.append(label);

    if (meta?.kind === 'text') {
      const copy = document.createElement('button');
      copy.textContent = 'Copy';
      copy.onclick = async () => {
        await navigator.clipboard.writeText(meta.text);
        toast('Copied');
      };
      bar.append(copy);
      const pre = document.createElement('pre');
      pre.textContent = meta.text;
      li.append(pre);
    } else if (meta?.kind === 'file') {
      const get = document.createElement('button');
      get.textContent = 'Download';
      get.onclick = () => download(item, meta);
      bar.append(get);

      if (meta.type?.startsWith('image/') && item.size <= MAX_PREVIEW) {
        const img = document.createElement('img');
        img.className = 'shot';
        img.alt = meta.name;
        li.append(img);
        showImage(item, meta, img);
      }
    }

    const del = document.createElement('button');
    del.textContent = '✕';
    del.title = 'Delete';
    del.setAttribute('aria-label', `Delete ${meta?.kind === 'file' ? meta.name : 'this item'}`);
    del.onclick = () => api(`/api/items/${item.id}?room=${room}`, { method: 'DELETE' });
    bar.append(del);

    li.prepend(bar);
    return li;
  }));
}

async function put(meta, body) {
  const res = await api(`/api/item?room=${room}`, {
    method: 'POST',
    headers: { 'x-meta': await sealMeta(key, meta), 'Content-Type': 'application/octet-stream' },
    body: body ?? new Uint8Array(),
  });
  if (!res.ok) throw new Error(`${res.status}`);
}

async function sendText() {
  const text = $('text').value;
  if (!text.trim()) return;
  $('send').disabled = true;
  try {
    await put({ kind: 'text', text });
    $('text').value = '';
    toast('Sent');
  } catch (err) {
    toast(`Failed (${err.message})`);
  } finally {
    $('send').disabled = false;
  }
}

async function upload(files) {
  for (const file of files) {
    if (file.size > MAX_FILE) {
      toast(`${file.name} is over ${bytes(MAX_FILE)}`);
      continue;
    }
    try {
      toast(`Encrypting ${file.name}…`);
      const sealed = await encrypt(key, await file.arrayBuffer());
      await put({ kind: 'file', name: file.name, type: file.type || 'application/octet-stream' }, sealed);
      toast(`${file.name} added`);
    } catch (err) {
      toast(`${file.name} failed (${err.message})`);
    }
  }
}

function wire() {
  $('send').onclick = sendText;
  $('text').onkeydown = (e) => { if (e.key === 'Enter' && (e.metaKey || e.ctrlKey)) sendText(); };
  $('pick').onclick = () => $('file').click();
  $('file').onchange = () => { upload($('file').files); $('file').value = ''; };
  $('clear').onclick = () => confirm('Delete everything in this cubby?') && api(`/api/items?room=${room}`, { method: 'DELETE' });

  $('pair').onclick = () => $('card').toggleAttribute('hidden');
  $('copycode').onclick = async () => {
    await navigator.clipboard.writeText($('code').textContent);
    toast('Code copied');
  };
  $('copylink').onclick = async () => {
    await navigator.clipboard.writeText(`${location.origin}/#${$('code').textContent}`);
    toast('Link copied');
  };
  $('forget').onclick = () => {
    if (!confirm('Unpair this device? Your other devices keep the cubby, and the code still opens it.')) return;
    localStorage.removeItem(SAVED);
    location.reload();
  };

  document.addEventListener('dragover', (e) => { e.preventDefault(); document.body.classList.add('dragging'); });
  document.addEventListener('dragleave', (e) => { if (!e.relatedTarget) document.body.classList.remove('dragging'); });
  document.addEventListener('drop', (e) => {
    e.preventDefault();
    document.body.classList.remove('dragging');
    if (e.dataTransfer.files.length) upload(e.dataTransfer.files);
  });
  document.addEventListener('paste', (e) => {
    // Only hijack the paste when it carries files; typing into the textarea should behave normally.
    const files = [...e.clipboardData.files];
    if (files.length) { e.preventDefault(); upload(files); }
  });
}

/**
 * Safari evicts localStorage for a site you have not opened in about a week,
 * which is exactly how a pairing dies over a holiday. A storage-persistence
 * grant exempts it; installing the page to the home screen is the other thing
 * that earns one. Ask, then say plainly which of the two you got.
 */
async function keepPaired() {
  const granted = (await navigator.storage?.persisted?.()) || (await navigator.storage?.persist?.()) || false;
  $('persist').textContent = granted
    ? 'Paired on this device until you unpair it — this browser has been told to keep it.'
    : 'This browser may forget the pairing if you go weeks without opening Cubby. Add it to your home screen and it will not.';
}

async function open(code) {
  ({ room, key } = await deriveIdentity(code));
  // Paired once, paired for good: the code lives here and nowhere on the server.
  localStorage.setItem(SAVED, normalize(code));
  history.replaceState(null, '', location.pathname); // keep the key out of the address bar
  $('code').textContent = format(code);
  keepPaired();
  $('gate').hidden = true;
  $('app').hidden = false;
  wire();

  // Live feed, with the browser's own reconnect handling the laptop going to sleep.
  const events = new EventSource(`/api/events?room=${room}`);
  events.onmessage = (e) => render(JSON.parse(e.data));
  events.onerror = () => toast('Reconnecting…');
}

function pairing() {
  $('gate').hidden = false;
  $('start').onclick = async () => {
    $('start').disabled = true;
    await open(newCode());
  };
  $('join').onsubmit = async (e) => {
    e.preventDefault();
    const code = normalize($('joincode').value);
    if (code.length < 8) return void ($('joinerr').textContent = 'That code looks too short.');
    $('joinerr').textContent = 'Deriving…';
    await open(code);
  };
}

async function main() {
  if (!globalThis.crypto?.subtle) {
    // No secure context, no encryption. Cubby does not have a plaintext mode to
    // fall back to, so say why rather than quietly downgrading.
    $('insecure').hidden = false;
    return;
  }
  const saved = localStorage.getItem(SAVED) || normalize(location.hash.slice(1));
  if (saved.length >= 8) await open(saved);
  else pairing();
}

// The pin, when the deployment has one, gates the page before any of this.
const auth = await (await api('/api/auth')).json();
if (auth.needsPin && !auth.ok) {
  $('pinform').hidden = false;
  $('pin').focus();
  $('pinform').onsubmit = async (e) => {
    e.preventDefault();
    const res = await api('/api/auth', { method: 'POST', body: $('pin').value });
    if (!res.ok) { $('pinerr').textContent = 'Wrong PIN.'; $('pin').select(); return; }
    $('pinform').hidden = true;
    await main();
  };
} else {
  await main();
}
