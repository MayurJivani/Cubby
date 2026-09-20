// The shared pile of stuff, keyed by room. Metadata lives in index.json, blobs
// live in blobs/<id>. Everything the server holds is opaque: `meta` is a
// ciphertext string it cannot read, and blobs are ciphertext bytes. It knows
// only which room, how big, and when.
//
// Everything is capped: by age, by items per room, by total bytes. Oldest first.
import { EventEmitter } from 'node:events';
import { randomUUID } from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';

const INDEX = 'index.json';
export const ROOM = /^[A-Za-z0-9_-]{4,64}$/;

export class Store extends EventEmitter {
  constructor({ dir, maxBytes = 512 * 1024 * 1024, maxItems = 100, ttlMs = 24 * 60 * 60 * 1000 } = {}) {
    super();
    this.dir = dir;
    this.blobs = path.join(dir, 'blobs');
    this.maxBytes = maxBytes;
    this.maxItems = maxItems; // per room
    this.ttlMs = ttlMs;
    fs.mkdirSync(this.blobs, { recursive: true });
    this.items = this.#load();
    this.prune();
  }

  #load() {
    try {
      const items = JSON.parse(fs.readFileSync(path.join(this.dir, INDEX), 'utf8'));
      // A blob that vanished under us (manual rm, half-finished upload) is not an item.
      return items.filter((it) => !it.blob || fs.existsSync(this.blobPath(it.id)));
    } catch {
      return [];
    }
  }

  #save() {
    fs.writeFileSync(path.join(this.dir, INDEX), JSON.stringify(this.items));
  }

  #changed(room) {
    this.#save();
    this.emit('change', room);
  }

  blobPath(id) {
    // ids are generated here, never taken from the client — nothing to traverse with.
    return path.join(this.blobs, id);
  }

  list(room) {
    this.prune();
    // Shares live in the same pile but are reachable only by their token —
    // otherwise anyone could ask a room for a listing of them.
    return this.items.filter((it) => it.room === room && !it.token);
  }

  share(token) {
    this.prune();
    return this.items.find((it) => it.token === token);
  }

  /** Reserve an id for an upload. Nothing is visible until add(). */
  begin() {
    const id = randomUUID();
    return { id, path: this.blobPath(id) };
  }

  add({ room, id = randomUUID(), meta, size = 0, blob = false, token, expiresAt, once }) {
    const item = { id, room, meta, size, blob, at: Date.now() };
    // A share carries its own deadline and its own way of dying.
    if (token) Object.assign(item, { token, expiresAt, once: Boolean(once) });
    this.items.unshift(item);
    this.prune();
    this.#changed(room);
    return item;
  }

  drop(id) {
    fs.rmSync(this.blobPath(id), { force: true });
  }

  get(id, room) {
    return this.items.find((it) => it.id === id && it.room === room);
  }

  remove(id, room) {
    const i = this.items.findIndex((it) => it.id === id && it.room === room);
    if (i === -1) return false;
    const [item] = this.items.splice(i, 1);
    if (item.blob) this.drop(item.id);
    this.#changed(room);
    return true;
  }

  clear(room) {
    this.items = this.items.filter((it) => {
      if (it.room !== room) return true;
      if (it.blob) this.drop(it.id);
      return false;
    });
    this.#changed(room);
  }

  /** Burn a one-time share the moment it has been handed over. */
  burn(token) {
    const i = this.items.findIndex((it) => it.token === token);
    if (i === -1) return false;
    const [item] = this.items.splice(i, 1);
    if (item.blob) this.drop(item.id);
    this.#save();
    return true;
  }

  /** Drop expired items, then oldest-first until under every cap. */
  prune() {
    const now = Date.now();
    const cutoff = now - this.ttlMs;
    const perRoom = new Map();
    const kept = [];
    const dropped = [];
    let bytes = 0;
    for (const item of this.items) {
      const count = perRoom.get(item.room) || 0;
      // A share expires on its own clock and is not part of any room's budget.
      if (item.token) {
        if (item.expiresAt < now) dropped.push(item);
        // Kept shares still count against the disk, so a pile of them squeezes
        // the rooms rather than quietly filling the volume.
        else (bytes += item.size, kept.push(item));
        continue;
      }
      if (item.at < cutoff || count >= this.maxItems || bytes + item.size > this.maxBytes) {
        dropped.push(item);
      } else {
        perRoom.set(item.room, count + 1);
        bytes += item.size;
        kept.push(item);
      }
    }
    if (!dropped.length) return 0;
    for (const item of dropped) if (item.blob) this.drop(item.id);
    this.items = kept;
    this.#save();
    return dropped.length;
  }
}
