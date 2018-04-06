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
const fs = require('bfile');
const constants = require('./constants');
const util = require('./util');
const wire = require('./wire');

const {
  types,
  codes
} = constants;

const {
  Message,
  Record
} = wire;

/*
 * Constants
 */

const ROOT_HINTS = require('./roothints');

/*
 * Cache
 */

let hints = null;

/**
 * Zone
 */

class Zone {
  constructor(origin) {
    this.origin = '.';
    this.count = 0;
    this.records = new Map();
    this.sigs = new Map();
    this.nsec = new NSECList(this);
    this.setOrigin(origin);
  }

  clear() {
    this.origin = '.';
    this.count = 0;
    this.clearRecords();
    return this;
  }

  clearRecords() {
    this.records.clear();
    this.sigs.clear();
    this.nsec.clear();
    return this;
  }

  setOrigin(origin) {
    if (origin == null)
      origin = '.';

    assert(util.isFQDN(origin));

    this.origin = origin.toLowerCase();
    this.count = util.countLabels(this.origin);

    return this;
  }

  insert(record) {
    assert(record instanceof Record);

    if (!util.isSubdomain(this.origin, record.name))
      throw new Error('Not a child of this zone.');

    if (record.type !== types.A && record.type !== types.AAAA) {
      if (util.countLabels(record.name) > this.count + 1)
        throw new Error('Too many labels.');
    }

    const rr = record.deepClone();

    // Lowercase.
    rr.canonical();

    if (!this.records.has(rr.name))
      this.records.set(rr.name, new RecordMap());

    const map = this.records.get(rr.name);

    if (!map.records.has(rr.type))
      map.records.set(rr.type, []);

    const rrs = map.records.get(rr.type);

    rrs.push(rr);

    switch (rr.type) {
      case types.RRSIG: {
        const {typeCovered} = rr.data;

        if (!map.sigs.has(typeCovered))
          map.sigs.set(typeCovered, []);

        const sigs = map.sigs.get(typeCovered);
        sigs.push(rr);

        break;
      }

      case types.NSEC: {
        this.nsec.insert(rr.name);
        break;
      }
    }

    return this;
  }

  push(name, type, ds, an) {
    assert(util.isFQDN(name));
    assert((type & 0xffff) === type);
    assert(typeof ds === 'boolean');
    assert(Array.isArray(an));

    const map = this.records.get(name);

    if (!map)
      return this;

    const rrs = map.records.get(type);

    if (!rrs || rrs.length === 0)
      return this;

    for (const rr of rrs)
      an.push(rr);

    if (ds) {
      const sigs = map.sigs.get(type);

      if (sigs) {
        for (const rr of sigs)
          an.push(rr);
      }
    }

    return this;
  }

  get(name, type, ds) {
    const an = [];
    this.push(name, type, ds, an);
    return an;
  }

  glue(name, ds, an) {
    assert(util.isFQDN(name));
    assert(typeof ds === 'boolean');
    assert(Array.isArray(an));

    this.push(name, types.A, ds, an);
    this.push(name, types.AAAA, ds, an);

    return this;
  }

  find(name, type, ds) {
    const an = this.get(name, type, ds);
    const ar = [];

    for (const rr of an) {
      switch (rr.type) {
        case types.CNAME:
          this.glue(rr.data.target, ds, an);
          break;
        case types.DNAME:
          this.glue(rr.data.target, ds, an);
          break;
        case types.NS:
          this.glue(rr.data.ns, ds, ar);
          break;
        case types.MX:
          this.glue(rr.data.mx, ds, ar);
          break;
      }
    }

    return [an, ar];
  }

  getHints() {
    if (!hints) {
      hints = wire.fromZone(ROOT_HINTS, '.');
      for (const rr of hints)
        rr.canonical();
    }

    const ns = [];
    const ar = [];

    for (const rr of hints) {
      switch (rr.type) {
        case types.NS:
          ns.push(rr);
          break;
        case types.A:
        case types.AAAA:
          ar.push(rr);
          break;
      }
    }

    return [ns, ar];
  }

  proveNoData(ns) {
    this.push(this.origin, types.NSEC, true, ns);
    return this;
  }

  proveNameError(name, ns) {
    const lower = this.nsec.lower(name);

    if (lower)
      this.push(lower, types.NSEC, true, ns);

    this.proveNoData(ns);

    return this;
  }

  query(name, type, ds) {
    assert(util.isFQDN(name));
    assert((type & 0xffff) === type);
    assert(typeof ds === 'boolean');

    const [an, ar] = this.find(name, type, ds);

    if (an.length > 0) {
      const aa = util.equal(name, this.origin);
      return [an, [], ar, aa, true];
    }

    const labels = util.split(name);

    if (this.origin !== '.') {
      const zone = util.from(name, labels, -this.count);

      // Refer them back to the root zone.
      if (this.origin !== zone) {
        const [ns, ar] = this.getHints();
        return [[], ns, ar, false, true];
      }
    }

    // Serve an SoA (no data).
    if (labels.length === this.count) {
      const ns = this.get(this.origin, types.SOA, ds);
      if (ds)
        this.proveNoData(ns);
      return [[], ns, [], true, false];
    }

    const index = this.count + 1;
    const child = util.from(name, labels, -index);
    const [ns, glue] = this.find(child, types.NS, ds);

    // Serve an SoA (nxdomain).
    if (ns.length === 0) {
      const ns = this.get(this.origin, types.SOA, ds);
      if (ds)
        this.proveNameError(child, ns);
      return [[], ns, [], false, false];
    }

    if (ds)
      this.push(child, types.DS, ds, ns);

    return [[], ns, glue, false, true];
  }

  resolve(name, type, ds) {
    assert(util.isFQDN(name));
    assert((type & 0xffff) === type);
    assert(typeof ds === 'boolean');

    const qname = name.toLowerCase();
    const qtype = type === types.ANY ? types.NS : type;
    const [an, ns, ar, aa, ok] = this.query(qname, qtype, ds);
    const msg = new Message();

    if (!aa && !ok)
      msg.code = codes.NXDOMAIN;

    msg.aa = aa;
    msg.answer = an;
    msg.authority = ns;
    msg.additional = ar;

    return msg;
  }

  fromString(text, file) {
    const rrs = wire.fromZone(text, this.origin, file);

    for (const rr of rrs)
      this.insert(rr);

    return this;
  }

  static fromString(origin, text, file) {
    return new this(origin).fromString(text, file);
  }

  fromFile(file) {
    const text = fs.readFileSync(file, 'utf8');
    return this.fromString(text, file);
  }

  static fromFile(origin, file) {
    return new this(origin).fromFile(file);
  }
}

/**
 * RecordMap
 */

class RecordMap {
  constructor() {
    // type -> rrs
    this.records = new Map();
    // type covered -> sigs
    this.sigs = new Map();
  }
}

/**
 * NSECList
 */

class NSECList {
  constructor(zone) {
    this.zone = zone;
    this.labels = [];
  }

  clear() {
    this.labels.length = 0;
    return this;
  }

  get origin() {
    return this.zone.origin;
  }

  get count() {
    return this.zone.count;
  }

  insert(name) {
    const labels = util.split(name);

    if (labels.length !== this.count + 1)
      return false;

    const index = this.count + 1;
    const label = util.label(name, labels, -index);

    return insertString(this.labels, label);
  }

  lower(name) {
    const index = this.count + 1;
    const label = util.label(name, -index);
    const lower = findLower(this.labels, label);

    if (!lower)
      return null;

    if (this.origin === '.')
      return `${lower}.`;

    return `${lower}.${this.origin}`;
  }
}

/*
 * Helpers
 */

function search(items, key, compare, insert) {
  let start = 0;
  let end = items.length - 1;

  while (start <= end) {
    const pos = (start + end) >>> 1;
    const cmp = compare(items[pos], key);

    if (cmp === 0)
      return pos;

    if (cmp < 0)
      start = pos + 1;
    else
      end = pos - 1;
  }

  if (!insert)
    return -1;

  return start;
}

function insert(items, item, compare, uniq) {
  const i = search(items, item, compare, true);

  if (uniq && i < items.length) {
    if (compare(items[i], item) === 0)
      return -1;
  }

  if (i === 0)
    items.unshift(item);
  else if (i === items.length)
    items.push(item);
  else
    items.splice(i, 0, item);

  return i;
}

function insertString(items, name) {
  return insert(items, name, util.compare, true) !== -1;
}

function findLower(items, name) {
  if (items.length === 0)
    return null;

  const i = search(items, name, util.compare, true);
  const match = items[i];
  const cmp = util.compare(match, name);

  if (cmp === 0)
    throw new Error('Not an NXDOMAIN.');

  if (cmp < 0)
    return match;

  if (i === 0)
    return null;

  return items[i - 1];
}

/*
 * Expose
 */

module.exports = Zone;
