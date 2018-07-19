/*!
 * hints.js - root hints object for bns
 * Copyright (c) 2018, Christopher Jeffrey (MIT License).
 * https://github.com/chjj/bns
 *
 * Parts of this software are based on solvere:
 *   https://github.com/rolandshoemaker/solvere
 */

'use strict';

const assert = require('bsert');
const fs = require('bfile');
const IP = require('binet');
const Authority = require('./authority');
const constants = require('./constants');
const dnssec = require('./dnssec');
const util = require('./util');
const wire = require('./wire');
const {DNS_PORT} = constants;

const {
  types,
  classes,
  Record,
  NSRecord,
  ARecord,
  AAAARecord
} = wire;

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
    this.port = DNS_PORT;
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
    this.port = DNS_PORT;
    return this;
  }

  getSystem() {
    if (process.platform === 'win32')
      return null;

    return '/var/named/root.hint';
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

  addServer(name, addr) {
    if (!util.isName(name))
      throw new Error('Invalid name.');

    if (!util.isIP(addr))
      throw new Error('Invalid IP.');

    name = name.toLowerCase();
    name = util.fqdn(name);

    if (this.ns.indexOf(name) === -1)
      this.ns.push(name);

    const ip = IP.toBuffer(addr);

    if (IP.isIPv4(ip))
      this.inet4.set(name, IP.toString(ip));
    else
      this.inet6.set(name, IP.toString(ip));

    return this;
  }

  removeServer(name) {
    if (!util.isName(name))
      throw new Error('Invalid name.');

    name = name.toLowerCase();
    name = util.fqdn(name);

    const i = this.ns.indexOf(name);

    if (i === -1)
      return this;

    this.ns.splice(i, 1);
    this.inet4.delete(name);
    this.inet6.delete(name);

    return this;
  }

  addAnchor(ds) {
    if (typeof ds === 'string')
      ds = Record.fromString(ds);

    assert(ds instanceof Record);

    if (ds.type === types.DNSKEY)
      ds = dnssec.createDS(ds, dnssec.hashes.SHA256);

    assert(ds.type === types.DS);

    if (ds.name !== '.')
      throw new Error('Invalid anchor name.');

    if (ds.class !== classes.IN)
      throw new Error('Invalid anchor class.');

    ds = ds.clone();

    if (ds.ttl === 0)
      ds.ttl = 3600000;

    this.anchors.push(ds);

    return this;
  }

  removeAnchor(ds) {
    if (typeof ds === 'string')
      ds = Record.fromString(ds);

    assert(ds instanceof Record);

    if (ds.type === types.DNSKEY)
      ds = dnssec.createDS(ds, dnssec.hashes.SHA256);

    assert(ds.type === types.DS);

    const raw = ds.data.encode();

    let i;
    for (i = 0; i < this.anchors.length; i++) {
      const ds = this.anchors[i];
      if (ds.data.encode().equals(raw))
        break;
    }

    if (i === this.anchors.length)
      return this;

    this.anchors.splice(i, 1);

    return this;
  }

  getAuthority(inet6) {
    if (this.ns.length === 0)
      throw new Error('No nameservers available.');

    const auth = new Authority('.', 'hints.local.');

    for (const name of this.ns) {
      if (inet6) {
        const host = this.inet6.get(name);
        if (host)
          auth.add(host, this.port);
      }

      const host = this.inet4.get(name);

      if (host)
        auth.add(host, this.port);
    }

    assert(auth.servers.length > 0);

    return auth;
  }

  _toRecord(name) {
    const records = [];

    const inet4 = this.inet4.get(name);
    const inet6 = this.inet6.get(name);

    const rr = new Record();
    const rd = new NSRecord();
    rr.name = '.';
    rr.ttl = 3600000;
    rr.type = types.NS;
    rr.data = rd;
    rd.ns = name.toUpperCase();

    records.push(rr);

    if (inet4) {
      const rr = new Record();
      const rd = new ARecord();
      rr.name = name.toUpperCase();
      rr.ttl = 3600000;
      rr.type = types.A;
      rr.data = rd;
      rd.address = inet4;
      records.push(rr);
    }

    if (inet6) {
      const rr = new Record();
      const rd = new AAAARecord();
      rr.name = name.toUpperCase();
      rr.ttl = 3600000;
      rr.type = types.AAAA;
      rr.data = rd;
      rd.address = inet6;
      records.push(rr);
    }

    return records;
  }

  toRecords() {
    const records = [];

    for (const ns of this.ns) {
      for (const rr of this._toRecord(ns))
        records.push(rr);
    }

    for (const ds of this.anchors)
      records.push(ds);

    return records;
  }

  toString() {
    let out = '';

    out += this.toHintString();

    if (this.anchors.length > 0)
      out += this.toAnchorString();

    return out;
  }

  toHintString() {
    let out = '';

    out += ';\n';
    out += '; Root Zone\n';
    out += '; (generated by bns)\n';
    out += ';\n';
    out += '\n';

    for (const ns of this.ns) {
      for (const rr of this._toRecord(ns))
        out += `${rr.toString()}\n`;
      out += '\n';
    }

    return out;
  }

  toAnchorString() {
    let out = '';

    out += ';\n';
    out += '; Trust Anchors\n';
    out += ';\n';
    out += '\n';

    for (const rr of this.anchors)
      out += `${rr.toString()}\n`;

    return out;
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
          this.anchors.push(rr.clone());
          break;
        }

        case types.DNSKEY: {
          const ds = dnssec.createDS(rr, dnssec.hashes.SHA256);
          this.anchors.push(ds);
          break;
        }
      }
    }

    return this;
  }

  static fromRecords(records) {
    return new this().fromRecords(records);
  }

  fromString(text) {
    const records = wire.fromZone(text);
    return this.fromRecords(records);
  }

  static fromString(text) {
    return new this().fromString(text);
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
    return this.fromString(ROOT_HINTS);
  }

  static fromRoot() {
    return new this().fromRoot();
  }

  fromFile(file) {
    assert(typeof file === 'string');
    const text = fs.readFileSync(file, 'utf8');
    return this.fromString(text);
  }

  static fromFile(file) {
    return new this().fromFile(file);
  }

  fromSystem() {
    const file = this.getSystem();

    if (file) {
      try {
        this.fromFile(file);
      } catch (e) {
        this.setDefault();
      }
    } else {
      this.setDefault();
    }

    return this;
  }

  static fromSystem() {
    return new this().fromSystem();
  }

  async fromFileAsync(file) {
    assert(typeof file === 'string');
    const text = await fs.readFile(file, 'utf8');
    return this.fromString(text);
  }

  static fromFileAsync(file) {
    return new this().fromFileAsync(file);
  }

  async fromSystemAsync() {
    const file = this.getSystem();

    if (file) {
      try {
        await this.fromFileAsync(file);
      } catch (e) {
        this.setDefault();
      }
    } else {
      this.setDefault();
    }

    return this;
  }

  static fromSystemAsync() {
    return new this().fromSystemAsync();
  }
}

/*
 * Expose
 */

module.exports = Hints;
