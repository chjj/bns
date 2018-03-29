/*!
 * hints.js - root hints object for bns
 * Copyright (c) 2018, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bns
 *
 * Parts of this software are based on solvere:
 *   https://github.com/rolandshoemaker/solvere
 */

'use strict';

const assert = require('assert');
const Authority = require('./authority');
const dnssec = require('./dnssec');
const wire = require('./wire');
const {types, Record} = wire;

/*
 * Constants
 */

const ROOT_HINTS = require('./roothints');

/**
 * Hints
 */

class Hints {
  constructor() {
    this.ns = [];
    this.inet4 = new Map();
    this.inet6 = new Map();
    this.anchors = [];
    this.port = 53;
  }

  inject(hints) {
    assert(hints instanceof this.constructor);

    this.ns = hints.ns.slice();

    this.inet4.clear();

    for (const [key, ip] of hints.inet4)
      this.inet4.set(key, ip);

    this.inet6.clear();

    for (const [key, ip] of hints.inet6)
      this.inet6.set(key, ip);

    this.anchors = hints.anchors.slice();
    this.port = hints.port;

    return this;
  }

  clone() {
    const copy = new this.constructor();
    return copy.inject(this);
  }

  clear() {
    this.ns.length = 0;
    this.inet4.clear();
    this.inet6.clear();
    this.anchors.length = 0;
    this.port = 53;
    return this;
  }

  setDefault() {
    return this.setRoot();
  }

  setLocal() {
    this.clear();
    this.ns.push('hints.local.');
    this.inet4.set('hints.local.', '127.0.0.1');
    this.inet6.set('hints.local.', '::1');
    return this;
  }

  setRoot() {
    this.clear();
    return this.fromRoot();
  }

  getAuthority(inet6) {
    if (this.ns.length === 0)
      throw new Error('No nameservers available.');

    const auth = new Authority('.', 'hints.local.');

    for (const name of this.ns) {
      let host;

      if (inet6 && this.inet6.has(name))
        host = this.inet6.get(name);
      else
        host = this.inet4.get(name);

      auth.add(host, this.port);
    }

    return auth;
  }

  fromRecords(records) {
    for (const rr of records) {
      const name = rr.name.toLowerCase();

      switch (rr.type) {
        case types.A: {
          this.inet4.set(name, rr.data.address);
          break;
        }
        case types.AAAA: {
          this.inet6.set(name, rr.data.address);
          break;
        }
      }
    }

    for (const rr of records) {
      const name = rr.name.toLowerCase();

      if (name !== '.')
        continue;

      switch (rr.type) {
        case types.NS: {
          const ns = rr.data.ns.toLowerCase();

          if (this.inet4.has(ns)
              || this.inet6.has(ns)) {
            this.ns.push(ns);
          }

          break;
        }

        case types.DS: {
          this.anchors.push(rr);
          break;
        }

        case types.DNSKEY: {
          const ds = dnssec.createDS(rr, dnssec.hashes.SHA256);
          this.anchors.push(ds);
          break;
        }
      }
    }

    assert(this.ns.length > 0);
    assert(this.inet4.size > 0 || this.inet6.size > 0);

    return this;
  }

  static fromRecords(records) {
    return new this().fromRecords(records);
  }

  fromZone(text) {
    const records = wire.fromZone(text);
    return this.fromRecords(records);
  }

  static fromZone(text) {
    return new this().fromZone(text);
  }

  fromJSON(json) {
    assert(Array.isArray(json));

    const records = [];
    for (const item of json)
      records.push(Record.fromJSON(item));

    return this.fromRecords(records);
  }

  static fromJSON(json) {
    return new this().fromJSON(json);
  }

  fromRoot() {
    return this.fromZone(ROOT_HINTS);
  }

  static fromRoot() {
    return new this().fromRoot();
  }
}

/*
 * Expose
 */

module.exports = Hints;
