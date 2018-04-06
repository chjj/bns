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

  insert(rr) {
    assert(rr instanceof Record);

    const name = rr.name.toLowerCase();
    const type = rr.type;

    if (!this.records.has(name))
      this.records.set(name, new RecordMap());

    const map = this.records.get(name);

    if (!map.records.has(type))
      map.records.set(type, []);

    const rrs = map.records.get(type);

    rrs.push(rr);

    if (type === types.RRSIG) {
      const {typeCovered} = rr.data;

      if (!map.sigs.has(typeCovered))
        map.sigs.set(typeCovered, []);

      const sigs = map.sigs.get(typeCovered);
      sigs.push(rr);
    }

    return this;
  }

  get(name, type, ds, res) {
    assert(util.isFQDN(name));
    assert((type & 0xffff) === type);

    const map = this.records.get(name);

    if (!map)
      return [];

    const rrs = map.records.get(type);

    if (!rrs || rrs.length === 0)
      return [];

    const result = res || [];

    for (const rr of rrs)
      result.push(rr);

    if (ds) {
      const sigs = map.sigs.get(type);

      if (sigs) {
        for (const rr of sigs)
          result.push(rr);
      }
    }

    return result;
  }

  glue(name, ds, res) {
    assert(util.isFQDN(name));

    name = name.toLowerCase();

    const result = res || [];

    this.get(name, types.A, ds, result);
    this.get(name, types.AAAA, ds, result);

    return result;
  }

  find(name, type, ds) {
    const an = this.get(name, type, ds);
    const ar = [];

    for (const rr of an) {
      switch (rr.type) {
        case types.NS:
          this.glue(rr.data.ns, ds, ar);
          break;
        case types.CNAME:
          this.glue(rr.data.target, ds, an);
          break;
        case types.DNAME:
          this.glue(rr.data.target, ds, an);
          break;
        case types.MX:
          this.glue(rr.data.mx, ds, ar);
          break;
      }
    }

    return [an, ar];
  }

  hints() {
    if (!hints)
      hints = wire.fromZone(ROOT_HINTS, '.');

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

  query(name, type, ds) {
    assert(util.isFQDN(name));
    assert((type & 0xffff) === type);
    assert(typeof ds === 'boolean');

    name = name.toLowerCase();

    if (type === types.ANY)
      type = types.NS;

    const [an, ar] = this.find(name, type, ds);

    if (an.length > 0) {
      const aa = name === this.origin;
      return [an, [], ar, aa, true];
    }

    const labels = util.split(name);

    if (this.origin !== '.') {
      const zone = util.from(name, labels, -this.count);

      // Refer them back to the root zone.
      if (this.origin !== zone) {
        const [ns, ar] = this.hints();
        return [[], ns, ar, false, true];
      }
    }

    // Serve an SoA (no data).
    if (labels.length === this.count) {
      const ns = this.get(this.origin, types.SOA, ds);
      if (ds) {
        this.get(this.origin, types.NSEC, ds, ns);
        this.get(this.origin, types.NSEC3, ds, ns);
      }
      return [[], ns, [], true, false];
    }

    const child = util.from(name, labels, -(this.count + 1));
    const [ns, glue] = this.find(child, types.NS, ds);

    // Serve an SoA (nxdomain).
    if (ns.length === 0) {
      const ns = this.get(this.origin, types.SOA, ds);
      // Todo: Serve NX proofs. We'll
      // need some kind of search tree.
      return [[], ns, [], false, false];
    }

    if (ds)
      this.get(child, types.DS, ds, ns);

    return [[], ns, glue, false, true];
  }

  resolve(name, type, ds) {
    const [an, ns, ar, aa, ok] = this.query(name, type, ds);
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

/*
 * Expose
 */

module.exports = Zone;
