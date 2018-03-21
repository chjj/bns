/*!
 * cache.js - resolver cache for bns
 * Copyright (c) 2018, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bns
 *
 * Parts of this software are based on solvere:
 *   https://github.com/rolandshoemaker/solvere
 */

'use strict';

const assert = require('assert');
const Heap = require('bheep');
const wire = require('./wire');
const util = require('./util');
const {Message} = wire;

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

  remove(id) {
    this.map.delete(id);
    return this;
  }

  hash(qs, zone) {
    return `${qs.name.toLowerCase()}${qs.type}${zone.toLowerCase()}`;
  }

  prune() {
    while (this.size > this.maxSize) {
      const [id, deadline] = this.queue.shift();
      const entry = this.get(id);

      if (entry && entry.deadline === deadline) {
        this.size -= entry.usage();
        this.size -= id.length * 2 + 20;
        this.remove(id);
      } else {
        this.size -= id.length * 2 + 20;
      }
    }

    return this;
  }

  insert(qs, zone, msg, ad, eternal = false) {
    const id = this.hash(qs, zone);
    const ttl = msg.minTTL();

    if (ttl === 0)
      return this;

    const item = this.get(id);

    if (item) {
      if (item.eternal)
        return this;

      const raw = msg.encode();

      this.size -= item.usage();

      item.msg = raw;
      item.setAD(ad);
      item.deadline = util.now() + ttl;

      this.size += item.usage();
      this.queue.insert([id, item.deadline]);
      this.size += id.length * 2 + 20;
      this.prune();

      return this;
    }

    const raw = msg.encode();
    const entry = new CacheEntry(raw);

    entry.setAD(ad);

    this.map.set(id, entry);
    this.size += entry.usage();

    if (eternal) {
      entry.eternal = true;
      entry.deadline = -1 >>> 0;
    } else {
      entry.deadline = util.now() + ttl;
      this.queue.insert([id, entry.deadline]);
      this.size += id.length * 2 + 20;
      this.prune();
    }

    return this;
  }

  hit(qs, zone) {
    const id = this.hash(qs, zone);
    const entry = this.map.get(id);

    if (!entry)
      return null;

    if (entry.expired()) {
      this.size -= entry.usage();
      this.remove(id);
      return null;
    }

    return Message.decode(entry.msg);
  }
}

/**
 * CacheEntry
 */

class CacheEntry {
  constructor(msg) {
    assert(Buffer.isBuffer(msg));
    this.msg = msg;
    this.deadline = 0;
    this.eternal = false;
  }

  usage() {
    return this.msg.length + 80 + 8 + 8;
  }

  setAD(ad) {
    let bits = this.msg.readUInt16BE(2, true);

    if (ad)
      bits |= wire.flags.AD;
    else
      bits &= ~wire.flags.AD;

    this.msg.writeUInt16BE(bits, 2, true);
  }

  expired() {
    if (this.eternal)
      return false;

    return util.now() > this.deadline;
  }
}

/*
 * Expose
 */

module.exports = Cache;
