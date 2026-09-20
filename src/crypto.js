// Everything the server stores is encrypted here first, with a key it never sees.
//
// The pairing code is the whole secret. From it we derive, with one PBKDF2 pass:
// an AES-GCM key (bytes 0-31) and the room id the server files things under
// (bytes 32-47). The room id is a one-way slice of the same stretched output, so
// holding it tells you nothing about the key.
//
// Codes are 16 characters from a 30-character alphabet — about 78 bits, short
// enough to read off a screen and type into a phone, which is why there is no QR
// code anywhere in this project.

const ALPHABET = '23456789ABCDEFGHJKMNPQRSTVWXYZ'; // no I, L, O, U, 0, 1
const SALT = new TextEncoder().encode('cubby.v1');
const ITERATIONS = 300_000;
const IV_BYTES = 12;

/** A fresh pairing code, grouped for reading aloud: XXXX-XXXX-XXXX-XXXX. */
export function newCode() {
  const bytes = crypto.getRandomValues(new Uint8Array(16));
  // Rejection-free: 256 % 30 != 0 skews the alphabet by ~2%, which costs well
  // under a bit of the 78 and is not worth a resampling loop.
  const code = [...bytes].map((b) => ALPHABET[b % ALPHABET.length]).join('');
  return code.match(/.{4}/g).join('-');
}

/** Codes get read aloud and typed. Take what was meant, ignore the rest. */
export function normalize(code) {
  return [...String(code).toUpperCase()].filter((c) => ALPHABET.includes(c)).join('');
}

export function format(code) {
  return normalize(code).match(/.{1,4}/g)?.join('-') ?? '';
}

/** code -> { room, key }. Deliberately slow: it is the only thing guarding a room. */
export async function deriveIdentity(code) {
  const normalized = normalize(code);
  if (normalized.length < 8) throw new Error('code too short');
  const base = await crypto.subtle.importKey('raw', new TextEncoder().encode(normalized), 'PBKDF2', false, ['deriveBits']);
  const bits = new Uint8Array(
    await crypto.subtle.deriveBits({ name: 'PBKDF2', salt: SALT, iterations: ITERATIONS, hash: 'SHA-256' }, base, 384),
  );
  const key = await crypto.subtle.importKey('raw', bits.slice(0, 32), 'AES-GCM', false, ['encrypt', 'decrypt']);
  return { room: b64url(bits.slice(32)), key };
}

// A share is for someone who has no pairing code, so it gets its own key —
// never the room key, which would hand over the whole cubby. The key rides in
// the link's fragment, which browsers do not send to servers.
export function newShareKey() {
  return crypto.subtle.generateKey({ name: 'AES-GCM', length: 256 }, true, ['encrypt', 'decrypt']);
}

export async function exportKey(key) {
  return b64url(new Uint8Array(await crypto.subtle.exportKey('raw', key)));
}

export function importKey(packed) {
  return crypto.subtle.importKey('raw', unb64url(packed), 'AES-GCM', false, ['encrypt', 'decrypt']);
}

/** iv || ciphertext, so a message carries everything needed to open it. */
export async function encrypt(key, data) {
  const iv = crypto.getRandomValues(new Uint8Array(IV_BYTES));
  const ct = new Uint8Array(await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, data));
  const out = new Uint8Array(iv.length + ct.length);
  out.set(iv);
  out.set(ct, iv.length);
  return out;
}

export async function decrypt(key, buf) {
  const bytes = new Uint8Array(buf);
  return crypto.subtle.decrypt({ name: 'AES-GCM', iv: bytes.subarray(0, IV_BYTES) }, key, bytes.subarray(IV_BYTES));
}

/** Item metadata — kind, filename, type, and short text — travels as one blob. */
export async function sealMeta(key, obj) {
  return b64(await encrypt(key, new TextEncoder().encode(JSON.stringify(obj))));
}

export async function openMeta(key, packed) {
  return JSON.parse(new TextDecoder().decode(await decrypt(key, unb64(packed))));
}

const b64 = (bytes) => btoa(String.fromCharCode(...bytes));
const unb64 = (s) => Uint8Array.from(atob(s), (c) => c.charCodeAt(0));
const b64url = (bytes) => b64(bytes).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
const unb64url = (s) => unb64(s.replace(/-/g, '+').replace(/_/g, '/'));
