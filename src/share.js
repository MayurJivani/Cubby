// The page a share link lands on. It holds no pairing and knows no room — the
// token in the path fetches the sealed copy, the key after the # opens it.
import { importKey, decrypt, openMeta } from './crypto.js';

const $ = (id) => document.getElementById(id);
const token = location.pathname.replace(/^\/s\//, '');

function fail(message) {
  $('state').textContent = message;
  $('state').className = 'hint warn';
}

function show(meta, bytes, once) {
  $('state').hidden = true;
  $('panel').hidden = false;
  $('burned').hidden = !once;

  if (meta.kind === 'text') {
    $('label').textContent = 'A note';
    const pre = document.createElement('pre');
    pre.textContent = meta.text;
    $('body').append(pre);
    const copy = document.createElement('button');
    copy.textContent = 'Copy the text';
    copy.onclick = () => navigator.clipboard.writeText(meta.text).then(() => (copy.textContent = 'Copied'));
    $('body').after(copy);
    return;
  }

  const size = bytes.byteLength;
  $('label').textContent = `${meta.name} · ${size < 1048576 ? `${Math.round(size / 1024)} KB` : `${(size / 1048576).toFixed(1)} MB`}`;
  const url = URL.createObjectURL(new Blob([bytes], { type: meta.type }));

  // Show it where showing it is the point; otherwise the file is the point.
  const kind = String(meta.type || '').split('/')[0];
  const viewer = { image: 'img', audio: 'audio', video: 'video' }[kind];
  if (viewer) {
    const el = document.createElement(viewer);
    el.src = url;
    if (viewer !== 'img') el.controls = true;
    el.alt = meta.name;
    $('body').append(el);
  }

  const save = $('save');
  save.hidden = false;
  save.onclick = () => {
    const a = document.createElement('a');
    a.href = url;
    a.download = meta.name;
    a.click();
  };
}

async function main() {
  if (!globalThis.crypto?.subtle) return fail('This link needs an https:// address to open — browsers only allow decryption there.');
  const packed = location.hash.slice(1);
  if (!token || !packed) return fail('This link is missing the part after the #, which is the half that opens it. Ask for the whole link again.');

  let res;
  try {
    res = await fetch(`/api/share/${encodeURIComponent(token)}`, { method: 'POST' });
  } catch {
    return fail('Could not reach the server.');
  }
  if (!res.ok) {
    return fail(res.status === 404
      ? 'This link has already been opened, or it expired. Shares do not come back.'
      : `The server said ${res.status}.`);
  }

  const once = res.headers.get('x-once') === '1';
  try {
    const key = await importKey(packed);
    const meta = await openMeta(key, res.headers.get('x-meta'));
    const body = await res.arrayBuffer();
    show(meta, body.byteLength ? await decrypt(key, body) : new ArrayBuffer(0), once);
  } catch {
    // The bytes are spent either way — an honest message beats a retry that
    // cannot work.
    fail('The key in this link does not open this share. If it was a one-time link, it has now been used up.');
  }
}

main();
