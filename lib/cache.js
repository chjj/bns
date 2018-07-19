/*!
 * cache.js - resolver cache for bns
 * Copyright (c) 2018, Christopher Jeffrey (MIT License).
 * https://github.com/chjj/bns
 *
 * Parts of this software are based on solvere:
 *   https://github.com/rolandshoemaker/solvere
 */

'use strict';

const assert = require('bsert');
const Heap = require('bheep');
const bio = require('bufio');
const wire = require('./wire');
const util = require('./util');
const {Message, Question} = wire;

/**
 * Cache
 */

class Cache {
  constructor() {
    this.map = new Map();
    this.queue = new Heap((a, b) => a[1] - b[1]);
    this.size = 0;
    this.maxSize = 5 << 20;
  }

  get(id) {
    return this.map.get(id) || null;
  }

  has(id) {
    return this.map.has(id);
  }

  set(id, entry) {
    this.map.set(id, entry);
    return this;
  }

  remove(id) {
    this.map.delete(id);
    return this;
  }

  hash(qs, zone) {
    const n = qs.name.toLowerCase();
    const t = qs.type.toString(10);
    const z = zone.toLowerCase();
    return `${n};${t};${z}`;
  }

  prune() {
    while (this.size > this.maxSize) {
      const [id, deadline] = this.queue.shift();
      const entry = this.get(id);

      if (entry && entry.deadline() === deadline) {
        this.size -= entry.usage(id);
        this.remove(id);
      }

      this.size -= queueUsage(id);
    }

    return this;
  }

  insert(qs, zone, msg, ad, eternal = false) {
    assert(qs instanceof Question);
    assert(typeof zone === 'string');
    assert(msg instanceof Message);
    assert(typeof ad === 'boolean');
    assert(typeof eternal === 'boolean');

    const id = this.hash(qs, zone);
    const ttl = msg.minTTL();

    if (ttl === 0)
      return this;

    const item = this.get(id);

    if (item) {
      if (item.eternal)
        return this;

      const raw = msg.encode();

      this.size -= item.usage(id);

      item.msg = raw;
      item.setAD(ad);
      item.time = util.now();
      item.ttl = ttl;

      this.size += item.usage(id);

      this.size += queueUsage(id);
      this.queue.insert([id, item.deadline()]);
      this.prune();

      return this;
    }

    const raw = msg.encode();
    const entry = new CacheEntry(raw);

    entry.setAD(ad);
    entry.time = util.now();
    entry.ttl = ttl;
    entry.eternal = eternal;

    this.set(id, entry);
    this.size += entry.usage(id);

    if (!eternal) {
      this.size += queueUsage(id);
      this.queue.insert([id, entry.deadline()]);
      this.prune();
    }

    return this;
  }

  hit(qs, zone) {
    assert(qs instanceof Question);
    assert(typeof zone === 'string');

    const id = this.hash(qs, zone);
    const entry = this.get(id);

    if (!entry)
      return null;

    const now = util.now();

    if (entry.expired(now)) {
      this.size -= entry.usage(id);
      this.remove(id);
      return null;
    }

    const msg = Message.decode(entry.msg);
    const diff = now - entry.time;

    assert(diff >= 0);

    for (const rr of msg.records()) {
      if (rr.isOPT())
        continue;

      if (rr.ttl === 0)
        continue;

      if (rr.ttl <= diff) {
        rr.ttl = 1;
        continue;
      }

      rr.ttl -= diff;
    }

    return msg;
  }
}

/**
 * CacheEntry
 */

class CacheEntry {
  constructor(msg) {
    assert(Buffer.isBuffer(msg));
    this.msg = msg;
    this.time = 0;
    this.ttl = 0;
    this.eternal = false;
  }

  deadline() {
    if (this.eternal)
      return 0xffffffff;

    return this.time + this.ttl;
  }

  usage(id) {
    let size = 0;
    size += id.length * 2;
    size += 80 + this.msg.length;
    size += 8 * 3;
    return size;
  }

  setAD(ad) {
    let bits = bio.readU16BE(this.msg, 2);

    if (ad)
      bits |= wire.flags.AD;
    else
      bits &= ~wire.flags.AD;

    bio.writeU16BE(this.msg, bits, 2);
  }

  expired(now) {
    // Someone changed
    // their system time.
    // Clear cache.
    if (now < this.time)
      return true;

    if (this.eternal)
      return false;

    return now >= this.deadline();
  }
}

/*
 * Helpers
 */

function queueUsage(id) {
  return id.length * 2 + 20;
}

/*
 * Expose
 */

module.exports = Cache;
