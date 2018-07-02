/*!
 * ownership.js - DNSSEC ownership proofs for bns
 * Copyright (c) 2018, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bns
 */

'use strict';

const assert = require('assert');
const bio = require('bufio');
const constants = require('./constants');
const crypto = require('./crypto');
const dnssec = require('./dnssec');
const encoding = require('./encoding');
const util = require('./util');
const wire = require('./wire');

const {
  types,
  typeToString,
  algs,
  hashes,
  KSK_2010,
  KSK_2017
} = constants;

const {
  readNameBR
} = encoding;

const {
  Record
} = wire;

/*
 * Constants
 */

const rootAnchors = [
  Record.fromString(KSK_2010),
  Record.fromString(KSK_2017)
];

/**
 * Ownership
 */

class Ownership {
  constructor(Resolver, secure, anchors) {
    if (Resolver == null)
      Resolver = null;

    if (secure == null)
      secure = false;

    if (anchors == null)
      anchors = rootAnchors;

    assert(Resolver === null || (typeof Resolver === 'function'));
    assert(typeof secure === 'boolean');
    assert(Array.isArray(anchors) && anchors.length > 0);

    this.Resolver = Resolver;
    this.servers = ['8.8.8.8', '8.8.4.4'];

    this.secure = secure;
    this.anchors = anchors.slice();
    this.minBits = secure ? 2048 : 1024;
    this.maxBits = 4096;

    this.Proof = Proof;
    this.OwnershipProof = Proof;
    this.Zone = Zone;
  }

  static get Proof() {
    return Proof;
  }

  static get OwnershipProof() {
    return Proof;
  }

  static get Zone() {
    return Zone;
  }

  parseData(name, items, extra) {
    return {
      name,
      items
    };
  }

  getData(proof, extra) {
    assert(proof instanceof this.Proof);

    try {
      return this._getData(proof, extra);
    } catch (e) {
      if (e.code === 'ERR_ASSERTION')
        throw e;
      return null;
    }
  }

  _getData(proof, extra) {
    assert(proof instanceof this.Proof);

    if (proof.zones.length < 2)
      throw new Error('Proof too short.');

    const zone = proof.zones[proof.zones.length - 1];

    if (zone.claim.length === 0)
      throw new Error('No claims available.');

    for (const rr of zone.claim) {
      if (rr.type !== types.TXT)
        continue;

      const rd = rr.data;

      let result;

      try {
        result = this.parseData(rr.name, rd.txt, extra);
      } catch (e) {
        if (e.code === 'ERR_ASSERTION')
          throw e;
        continue;
      }

      if (result == null)
        continue;

      return result;
    }

    return null;
  }

  isSane(proof) {
    assert(proof instanceof this.Proof);

    if (proof.zones.length < 2)
      return false;

    let parent = '';

    for (let i = 0; i < proof.zones.length; i++) {
      const zone = proof.zones[i];
      const isLast = i === proof.zones.length - 1;

      if (!this.checkSanity(zone, parent, isLast))
        return false;

      parent = zone.keys[0].name;
    }

    return true;
  }

  verifyTimes(proof, time) {
    assert(proof instanceof this.Proof);
    assert(Number.isSafeInteger(time) && time >= 0);

    if (proof.zones.length < 2)
      return false;

    for (const zone of proof.zones) {
      if (!this.checkTimes(zone, time))
        return false;
    }

    return true;
  }

  verifySignatures(proof, anchors) {
    if (anchors == null)
      anchors = this.anchors;

    assert(proof instanceof this.Proof);
    assert(Array.isArray(anchors));

    if (proof.zones.length < 2)
      return false;

    if (anchors.length === 0)
      return false;

    let ds = anchors;
    let i = 0;

    for (; i < proof.zones.length - 1; i++) {
      const zone = proof.zones[i];
      const zskMap = this.verifyZone(zone, ds);

      if (!zskMap)
        return false;

      if (!this.verifyRecords(zone.referral, zskMap))
        return false;

      ds = util.extractSet(zone.referral, '', types.DS);
    }

    const zone = proof.zones[i];
    const zskMap = this.verifyZone(zone, ds);

    if (!zskMap)
      return false;

    if (!this.verifyRecords(zone.claim, zskMap))
      return false;

    return true;
  }

  checkSanity(zone, parent, isLast) {
    assert(zone instanceof Zone);
    assert(typeof parent === 'string');
    assert(typeof isLast === 'boolean');

    if (zone.keys.length === 0)
      return false;

    if (isLast) {
      if (zone.referral.length !== 0)
        return false;

      if (zone.claim.length === 0)
        return false;
    } else {
      if (zone.referral.length === 0)
        return false;

      if (zone.claim.length !== 0)
        return false;
    }

    const covered = new Set();
    const zoneName = zone.keys[0].name;
    const zoneLabels = util.countLabels(zoneName);

    if (!this.isChild(parent, zoneName))
      return false;

    for (const rr of zone.keys) {
      assert(rr instanceof Record);

      if (!util.equal(rr.name, zoneName))
        return false;

      const rd = rr.data;

      switch (rr.type) {
        case types.RRSIG:
          if (rd.typeCovered !== types.DNSKEY)
            return false;

          if (!this.isValidAlg(rd.algorithm))
            return false;

          if (rd.labels !== zoneLabels)
            return false;

          if (!util.equal(rd.signerName, zoneName))
            return false;

          covered.add(rd.typeCovered);

          break;
        case types.DNSKEY:
          if (!this.isValidAlg(rd.algorithm))
            return false;

          if (rd.protocol !== 3)
            return false;

          if (this.isRSA(rd.algorithm)) {
            const bits = crypto.rsaBits(rd.publicKey);

            if (bits < this.minBits || bits > this.maxBits)
              return false;
          }

          break;
        default:
          return false;
      }
    }

    for (const rr of zone.claim) {
      assert(rr instanceof Record);

      if (!util.equal(rr.name, zoneName))
        return false;

      const rd = rr.data;

      switch (rr.type) {
        case types.RRSIG:
          if (rd.typeCovered !== types.TXT)
            return false;

          if (!this.isValidAlg(rd.algorithm))
            return false;

          if (rd.labels !== zoneLabels)
            return false;

          if (!util.equal(rd.signerName, zoneName))
            return false;

          covered.add(rd.typeCovered);

          break;
        case types.TXT:
          break;
        default:
          return false;
      }
    }

    if (zone.referral.length > 0) {
      const dsName = zone.referral[0].name;
      const dsLabels = util.countLabels(dsName);

      if (!this.isChild(zoneName, dsName))
        return false;

      for (const rr of zone.referral) {
        assert(rr instanceof Record);

        if (!util.equal(rr.name, dsName))
          return false;

        const rd = rr.data;

        switch (rr.type) {
          case types.RRSIG:
            if (rd.typeCovered !== types.DS)
              return false;

            if (!this.isValidAlg(rd.algorithm))
              return false;

            if (rd.labels !== dsLabels)
              return false;

            if (!util.equal(rd.signerName, zoneName))
              return false;

            covered.add(rd.typeCovered);

            break;
          case types.DS:
            if (!this.isValidAlg(rd.algorithm))
              return false;

            if (!this.isValidHash(rd.digestType))
              return false;

            break;
          default:
            return false;
        }
      }
    }

    for (const rr of zone.records()) {
      assert(rr instanceof Record);

      if (rr.type === types.RRSIG)
        continue;

      if (!covered.has(rr.type))
        return false;
    }

    return true;
  }

  checkTimes(zone, time) {
    assert(zone instanceof Zone);
    assert(Number.isSafeInteger(time) && time >= 0);

    for (const rr of zone.records()) {
      assert(rr instanceof Record);

      if (rr.type !== types.RRSIG)
        continue;

      const rd = rr.data;

      if (!rd.validityPeriod(time))
        return false;
    }

    return true;
  }

  verifyChain(rrs, ds) {
    assert(Array.isArray(rrs));
    assert(Array.isArray(ds));

    if (rrs.length === 0)
      return false;

    if (ds.length === 0)
      return false;

    const keys = new Map();

    for (const rr of rrs) {
      assert(rr instanceof Record);

      if (rr.type !== types.DNSKEY)
        continue;

      const rd = rr.data;

      keys.set(rd.keyTag(), rr);
    }

    if (keys.length === 0)
      return null; // No keys.

    const kskMap = new Map();

    for (const rr of ds) {
      assert(rr instanceof Record);
      assert(rr.type === types.DS);

      const rd = rr.data;
      const dnskey = keys.get(rd.keyTag);

      if (!dnskey)
        continue;

      const ds = dnssec.createDS(dnskey, rd.digestType);

      if (!ds)
        continue; // Failed to convert KSK (unknown alg).

      if (!ds.data.digest.equals(rd.digest))
        return null; // Mismatching DS.

      if (ds.data.algorithm !== rd.algorithm)
        return null; // Mismatching DS.

      kskMap.set(rd.keyTag, dnskey);

      // Allow upgrading implicitly.
      if (this.secure && this.isSHA1(rd.algorithm)) {
        const key = dnskey.deepClone();
        const keyData = key.data;

        keyData.algorithm = algs.RSASHA256;

        const keyTag = keyData.keyTag();

        if (!kskMap.has(keyTag))
          kskMap.set(keyTag, key);
      }
    }

    if (kskMap.size === 0)
      return null; // No valid keys.

    return kskMap;
  }

  verifyKeys(rrs, kskMap) {
    assert(Array.isArray(rrs));
    assert(kskMap instanceof Map);

    if (rrs.length === 0)
      return null; // No keys

    if (kskMap.size === 0)
      return null; // No keys

    const keys = [];
    const sigs = [];

    for (const rr of rrs) {
      assert(rr instanceof Record);

      const rd = rr.data;

      if (rr.type === types.DNSKEY) {
        keys.push(rr);
        continue;
      }

      if (rr.type === types.RRSIG) {
        if (rd.typeCovered !== types.DNSKEY)
          continue;

        if (!kskMap.has(rd.keyTag))
          continue;

        sigs.push(rr);
        continue;
      }
    }

    if (keys.length === 0)
      return null; // No keys

    if (sigs.length === 0)
      return null; // No sigs

    const zskMap = new Map();

    for (const sig of sigs) {
      const s = sig.data;

      if (this.secure && this.isSHA1(s.algorithm))
        return null; // Insecure Signature.

      const dnskey = kskMap.get(s.keyTag);

      if (!dnskey)
        return null; // Missing DNS Key

      if (!dnssec.verify(sig, dnskey, keys))
        return null; // Invalid Signature
    }

    for (const rr of keys)
      zskMap.set(rr.data.keyTag(), rr);

    return zskMap;
  }

  verifyRecords(rrs, zskMap) {
    assert(zskMap instanceof Map);
    assert(Array.isArray(rrs));

    const set = new Set();

    for (const rr of rrs) {
      assert(rr instanceof Record);

      // No signed signatures.
      if (rr.type === types.RRSIG)
        continue;

      // Keys are already verified.
      if (rr.type === types.DNSKEY)
        continue;

      set.add(rr.type);
    }

    if (set.size === 0)
      return true;

    for (const rr of rrs) {
      if (rr.type !== types.RRSIG)
        continue;

      const s = rr.data;

      if (!set.has(s.typeCovered))
        continue;

      const dnskey = zskMap.get(s.keyTag);

      if (!dnskey)
        continue; // Missing DNS Key

      const rrset = util.extractSet(rrs, rr.name, s.typeCovered);

      if (rrset.length === 0)
        continue; // Missing Signed

      if (this.secure && this.isSHA1(s.algorithm))
        continue; // Insecure Signature.

      if (!dnssec.verify(rr, dnskey, rrset))
        continue; // Invalid Signature

      set.delete(s.typeCovered);
    }

    if (set.size !== 0)
      return false; // Unsigned Data

    return true;
  }

  verifyZone(zone, ds) {
    assert(zone instanceof Zone);

    const kskMap = this.verifyChain(zone.keys, ds);

    if (!kskMap)
      return null;

    return this.verifyKeys(zone.keys, kskMap);
  }

  isValidAlg(algorithm) {
    assert((algorithm & 0xff) === algorithm);

    switch (algorithm) {
      case algs.RSASHA1:
      case algs.RSASHA1NSEC3SHA1:
        // SHA1 insecurity handled elsewhere.
      case algs.RSASHA256:
      case algs.RSASHA512:
      case algs.ECDSAP256SHA256:
      case algs.ECDSAP384SHA384:
      case algs.ED25519:
        return true;
      default:
        return false;
    }
  }

  isValidHash(digestType) {
    assert((digestType & 0xff) === digestType);

    switch (digestType) {
      case hashes.SHA1:
        // Cannot ever accept SHA1 hashes.
        if (this.secure)
          return false;
      case hashes.SHA256:
      case hashes.SHA384:
      case hashes.SHA512:
        return true;
      default:
        return false;
    }
  }

  isRSA(algorithm) {
    assert((algorithm & 0xff) === algorithm);

    switch (algorithm) {
      case algs.RSASHA1:
      case algs.RSASHA1NSEC3SHA1:
      case algs.RSASHA256:
      case algs.RSASHA512:
        return true;
      default:
        return false;
    }
  }

  isSHA1(algorithm) {
    assert((algorithm & 0xff) === algorithm);

    switch (algorithm) {
      case algs.RSASHA1:
      case algs.RSASHA1NSEC3SHA1:
        return true;
      default:
        return false;
    }
  }

  isChild(parent, child) {
    assert(typeof parent === 'string');
    assert(typeof child === 'string');

    if (parent === '')
      return child === '.';

    const labels = util.countLabels(parent);

    if (util.countLabels(child) !== labels + 1)
      return false;

    if (!util.isSubdomain(parent, child))
      return false;

    return true;
  }

  async prove(name, estimate = false) {
    assert(typeof name === 'string');
    assert(typeof estimate === 'boolean');

    name = util.fqdn(name);

    if (!encoding.isName(name))
      throw new Error(`Invalid name for proof: ${JSON.stringify(name)}.`);

    const {Resolver} = this;

    if (!Resolver)
      throw new Error('No resolver available.');

    const stub = new Resolver({
      rd: true,
      cd: true,
      edns: true,
      ednsSize: 4096,
      dnssec: true,
      hosts: [
        ['localhost.', '127.0.0.1'],
        ['localhost.', '::1']
      ],
      servers: this.servers
    });

    await stub.open();

    try {
      return await this._prove(stub, name, estimate);
    } finally {
      await stub.close();
    }
  }

  async _prove(stub, name, estimate) {
    assert(stub instanceof this.Resolver);
    assert(typeof name === 'string');
    assert(typeof estimate === 'boolean');

    const labels = util.split(name);

    assert(labels.length > 0);

    const zones = [];
    const target = new Zone();

    try {
      target.claim = await this._lookup(stub, name, types.TXT);
    } catch (e) {
      if (!estimate)
        throw e;
    }

    target.keys = await this._lookup(stub, name, types.DNSKEY);

    zones.push(target);

    for (let i = 1; i <= labels.length; i++) {
      let parent = '.';

      if (i < labels.length)
        parent = util.from(name, labels, i);

      const zone = new Zone();
      zone.referral = await this._lookup(stub, name, types.DS);
      zone.keys = await this._lookup(stub, parent, types.DNSKEY);
      zones.push(zone);

      name = parent;
    }

    zones.reverse();

    const proof = new this.Proof();
    proof.zones = zones;

    if (estimate)
      return proof;

    if (!this.isSane(proof))
      throw new Error('Proof failed sanity check.');

    if (!this.verifyTimes(proof, util.now()))
      throw new Error('Proof contains expired signature.');

    if (!this.verifySignatures(proof))
      throw new Error('Proof failed signature check.');

    return proof;
  }

  async _lookup(stub, name, type) {
    assert(stub instanceof this.Resolver);

    const res = await stub.lookup(name, type);
    const rrs = [];

    for (const rr of res.answer) {
      if (!util.equal(rr.name, name))
        continue;

      switch (rr.type) {
        case type:
        case types.RRSIG:
          rrs.push(rr);
          break;
      }
    }

    const result = this.filterResponse(rrs);

    if (!util.hasType(result, type)) {
      const sym = typeToString(type);
      throw new Error(`No ${sym} records for ${name}`);
    }

    if (!util.hasType(result, types.RRSIG)) {
      const sym = typeToString(type);
      throw new Error(`No RRSIG(${sym}) records for ${name}`);
    }

    return result;
  }

  filterResponse(answer) {
    assert(Array.isArray(answer));

    const rrs = [];
    const dsMap = new Map();
    const now = util.now();

    for (const rr of answer) {
      assert(rr instanceof Record);

      const rd = rr.data;

      switch (rr.type) {
        case types.DS: {
          if (!this.isValidHash(rd.digestType))
            continue;

          if (!this.isValidAlg(rd.algorithm))
            continue;

          const old = dsMap.get(rd.keyTag);

          // Prefer higher security and de-duplicate.
          if (!old || old.data.digestType < rd.digestType)
            dsMap.set(rd.keyTag, rr);

          continue;
        }

        case types.DNSKEY: {
          if (!this.isValidAlg(rd.algorithm))
            continue;

          if (rd.protocol !== 3)
            continue;

          if (this.isRSA(rd.algorithm)) {
            const bits = crypto.rsaBits(rd.publicKey);

            if (bits < this.minBits || bits > this.maxBits)
              continue;
          }

          break;
        }

        case types.TXT: {
          break;
        }

        case types.RRSIG: {
          if (!this.isValidAlg(rd.algorithm))
            continue;

          if (!rd.validityPeriod(now))
            continue;

          if (this.secure && this.isSHA1(rd.algorithm))
            continue;

          break;
        }

        default: {
          continue;
        }
      }

      rrs.push(rr);
    }

    for (const rr of dsMap.values())
      rrs.push(rr);

    return rrs;
  }
}

/**
 * Proof
 * @extends {bufio.Struct}
 */

class Proof extends bio.Struct {
  constructor() {
    super();
    this.zones = [];
  }

  get target() {
    if (this.zones.length < 2)
      return '.';

    const zone = this.zones[this.zones.length - 1];

    if (zone.claim.length === 0)
      return '.';

    return zone.claim[0].name.toLowerCase();
  }

  *records() {
    for (const zone of this.zones) {
      for (const rr of zone.records())
        yield rr;
    }
  }

  inject(msg) {
    assert(msg instanceof this.constructor);
    this.zones = msg.zones.slice();
    return this;
  }

  deepClone() {
    const msg = new this.constructor();
    return msg.decode(this.encode());
  }

  canonical() {
    for (const zone of this.zones)
      zone.canonical();

    return this;
  }

  getSize(map) {
    let size = 1;

    for (const zone of this.zones)
      size += zone.getSize(map);

    return size;
  }

  write(bw, map) {
    bw.writeU8(this.zones.length);

    for (const zone of this.zones)
      zone.write(bw, map);

    return this;
  }

  read(br) {
    const zoneCount = br.readU8();

    for (let i = 0; i < zoneCount; i++) {
      const zone = Zone.read(br);
      this.zones.push(zone);
    }

    return this;
  }

  getJSON() {
    return {
      zones: this.zones.map(zone => zone.toJSON())
    };
  }

  fromJSON(json) {
    assert(json && typeof json === 'object');
    assert(Array.isArray(json.zones));

    for (const zone of json.zones)
      this.zones.push(Zone.fromJSON(zone));

    return this;
  }
}

/**
 * Zone
 * @extends {bufio.Struct}
 */

class Zone extends bio.Struct {
  constructor() {
    super();
    this.keys = [];
    this.claim = [];
    this.referral = [];
  }

  *records() {
    for (const rr of this.keys)
      yield rr;

    for (const rr of this.claim)
      yield rr;

    for (const rr of this.referral)
      yield rr;
  }

  inject(msg) {
    assert(msg instanceof this.constructor);
    this.keys = msg.keys.slice();
    this.claim = msg.claim.slice();
    this.referral = msg.referral.slice();
    return this;
  }

  deepClone() {
    const msg = new this.constructor();
    return msg.decode(this.encode());
  }

  canonical() {
    for (const rr of this.keys)
      rr.canonical();

    for (const rr of this.claim)
      rr.canonical();

    for (const rr of this.referral)
      rr.canonical();

    return this;
  }

  getSize(map) {
    let size = 1;

    for (const rr of this.keys)
      size += rr.getSize(map);

    size += 1;

    for (const rr of this.claim)
      size += rr.getSize(map);

    size += 1;

    for (const rr of this.referral)
      size += rr.getSize(map);

    return size;
  }

  write(bw, map) {
    bw.writeU8(this.keys.length);

    for (const rr of this.keys)
      rr.write(bw, map);

    bw.writeU8(this.claim.length);

    for (const rr of this.claim)
      rr.write(bw, map);

    bw.writeU8(this.referral.length);

    for (const rr of this.referral)
      rr.write(bw, map);

    return this;
  }

  read(br) {
    const rrCount = br.readU8();

    for (let i = 0; i < rrCount; i++) {
      const rr = readRecord(br, types.DNSKEY);
      this.keys.push(rr);
    }

    const claimCount = br.readU8();

    for (let i = 0; i < claimCount; i++) {
      const rr = readRecord(br, types.TXT);
      this.claim.push(rr);
    }

    const dsCount = br.readU8();

    for (let i = 0; i < dsCount; i++) {
      const rr = readRecord(br, types.DS);
      this.referral.push(rr);
    }

    return this;
  }

  getJSON() {
    return {
      keys: this.keys.map(rr => rr.toJSON()),
      claim: this.claim.map(rr => rr.toJSON()),
      referral: this.referral.map(rr => rr.toJSON())
    };
  }

  fromJSON(json) {
    assert(json && typeof json === 'object');
    assert(Array.isArray(json.keys));
    assert(Array.isArray(json.referral));

    for (const rr of json.keys)
      this.keys.push(Record.fromJSON(rr));

    for (const rr of json.claim)
      this.claim.push(Record.fromJSON(rr));

    for (const rr of json.referral)
      this.referral.push(Record.fromJSON(rr));

    return this;
  }
}

/*
 * Helpers
 */

function isSafeRecord(br, expect) {
  const offset = br.offset;

  let ret = false;

  try {
    ret = _isSafeRecord(br, expect);
  } catch (e) {
    ;
  }

  br.offset = offset;

  return ret;
}

function _isSafeRecord(br, expect) {
  readNameBR(br, false);

  const type = br.readU16BE();

  if (type === types.RRSIG) {
    br.seek(8 + 18);
    readNameBR(br, false);
    return true;
  }

  return type === expect;
}

function readRecord(br, expect) {
  assert(br);
  assert((expect & 0xffff) === expect);

  // We don't allow compression
  // or types we don't expect.
  if (!isSafeRecord(br, expect))
    throw new Error('Record unsafe to read.');

  return Record.read(br);
}

/*
 * Expose
 */

module.exports = Ownership;
