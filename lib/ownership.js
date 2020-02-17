/*!
 * ownership.js - DNSSEC ownership proofs for bns
 * Copyright (c) 2018, Christopher Jeffrey (MIT License).
 * https://github.com/chjj/bns
 */

'use strict';

const assert = require('bsert');
const bio = require('bufio');
const constants = require('./constants');
const crypto = require('./internal/crypto');
const dnssec = require('./dnssec');
const encoding = require('./encoding');
const util = require('./util');
const wire = require('./wire');

const {
  types,
  typeToString,
  algs,
  hashes,
  keyFlags,
  KSK_2017
} = constants;

const {
  readNameBR
} = encoding;

const {
  Record,
  TXTRecord
} = wire;

/*
 * Constants
 */

const rootAnchors = [
  Record.fromString(KSK_2017)
];

/**
 * Ownership
 */

class Ownership {
  constructor() {
    this.Resolver = null;
    this.servers = ['8.8.8.8', '8.8.4.4'];

    this.secure = true;
    this.anchors = rootAnchors.slice();
    this.minBits = 1017;
    this.strongBits = 2041;
    this.maxBits = 4096;
    this.ignore = false;

    this.rootAnchors = rootAnchors;
    this.Proof = Proof;
    this.OwnershipProof = Proof;
    this.Zone = Zone;
  }

  hasPrefix(proof, target, items) {
    return false;
  }

  isData(proof, target, items, extra) {
    return true;
  }

  parseData(proof, target, items, extra) {
    return {
      target,
      items
    };
  }

  addData(proof, items) {
    assert(proof instanceof this.Proof);
    assert(Array.isArray(items));

    if (items.length === 0)
      throw new Error('No items provided.');

    if (proof.zones.length < 2)
      throw new Error('Incomplete proof.');

    const zone = proof.zones[proof.zones.length - 1];

    if (zone.claim.length === 0)
      throw new Error('Zone has no claim records.');

    const rr = new Record();
    const rd = new TXTRecord();

    rr.name = zone.claim[0].name.toLowerCase();
    rr.type = types.TXT;
    rr.class = zone.claim[0].class;
    rr.ttl = zone.claim[0].ttl;
    rr.data = rd;

    for (const txt of items) {
      assert(typeof txt === 'string');
      rd.txt.push(txt);
    }

    const sig = zone.claim.pop();

    zone.claim.push(rr);
    zone.claim.push(sig);

    return rr;
  }

  removeData(proof) {
    assert(proof instanceof this.Proof);

    if (proof.zones.length < 2)
      return false;

    const zone = proof.zones[proof.zones.length - 1];

    if (zone.claim.length === 0)
      return false;

    zone.claim = this.filterSet(proof, zone.claim);

    return true;
  }

  filterSet(proof, rrs) {
    assert(proof instanceof this.Proof);
    assert(Array.isArray(rrs));

    const rrset = [];

    if (rrs.length === 0)
      return rrset;

    const target = rrs[0].name.toLowerCase();

    for (const rr of rrs) {
      assert(rr instanceof Record);

      const rd = rr.data;

      if (rr.type === types.TXT && rd.txt.length > 0) {
        if (this.hasPrefix(proof, target, rd.txt))
          continue;
      }

      rrset.push(rr);
    }

    return rrset;
  }

  filterClaim(proof, rrs) {
    if (!this.ignore)
      return rrs;

    return this.filterSet(proof, rrs);
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
      return null;

    const zone = proof.zones[proof.zones.length - 1];

    if (zone.claim.length === 0)
      return null;

    const target = zone.claim[0].name.toLowerCase();

    for (const rr of zone.claim) {
      if (rr.type !== types.TXT)
        continue;

      const rd = rr.data;

      if (rd.txt.length === 0)
        continue;

      if (!this.isData(proof, target, rd.txt, extra))
        continue;

      let result = null;

      try {
        result = this.parseData(proof, target, rd.txt, extra);
      } catch (e) {
        if (e.code === 'ERR_ASSERTION')
          throw e;
      }

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

    const [start, end] = this.getWindow(proof);

    return time >= start && time <= end;
  }

  verifySignatures(proof) {
    assert(proof instanceof this.Proof);

    if (proof.zones.length < 2)
      return false;

    let ds = this.anchors;
    let i = 0;

    for (; i < proof.zones.length - 1; i++) {
      const zone = proof.zones[i];

      if (!this.verifyKeys(zone, ds))
        return false;

      if (!this.verifyRecords(zone.referral, zone.keys))
        return false;

      ds = util.extractSet(zone.referral, '', types.DS);
    }

    const zone = proof.zones[i];

    if (!this.verifyKeys(zone, ds))
      return false;

    const claim = this.filterClaim(proof, zone.claim);

    if (!this.verifyRecords(claim, zone.keys))
      return false;

    return true;
  }

  isWeak(proof) {
    assert(proof instanceof this.Proof);

    if (proof.zones.length < 2)
      return false;

    for (const zone of proof.zones) {
      const ksk = extractKey(zone.keys, zone.keys);

      if (ksk && this.isRSA(ksk.data.algorithm)) {
        const bits = crypto.rsaBits(ksk.data.publicKey);

        if (bits < this.strongBits)
          return true; // Insecure Signature.
      }

      const zsk = extractKey(zone.body, zone.keys);

      if (zsk && this.isRSA(zsk.data.algorithm)) {
        const bits = crypto.rsaBits(zsk.data.publicKey);

        if (bits < this.strongBits)
          return true; // Insecure Signature.
      }
    }

    return false;
  }

  getWindow(proof) {
    assert(proof instanceof this.Proof);

    let start = -1;
    let end = -1;

    for (const rr of proof.records()) {
      assert(rr instanceof Record);

      if (rr.type !== types.RRSIG)
        continue;

      const rd = rr.data;

      if (start === -1 || rd.inception > start)
        start = rd.inception;

      if (end === -1 || rd.expiration < end)
        end = rd.expiration;
    }

    if (start === -1 || end === -1)
      return [0, 0];

    if (start > end)
      return [0, 0];

    return [start, end];
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

    const zoneName = zone.keys[0].name;
    const zoneLabels = util.countLabels(zoneName);

    if (!this.isChild(parent, zoneName))
      return false;

    let sawKeys = false;

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

          if (sawKeys)
            return false;

          sawKeys = true;

          break;
        case types.DNSKEY:
          break;
        default:
          return false;
      }
    }

    if (!sawKeys)
      return false;

    if (zone.claim.length > 0) {
      let sawClaim = false;

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

            if (sawClaim)
              return false;

            sawClaim = true;

            break;
          case types.TXT:
            break;
          default:
            return false;
        }
      }

      if (!sawClaim)
        return false;
    }

    if (zone.referral.length > 0) {
      const dsName = zone.referral[0].name;
      const dsLabels = util.countLabels(dsName);

      if (!this.isChild(zoneName, dsName))
        return false;

      let sawReferral = false;

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

            if (sawReferral)
              return false;

            sawReferral = true;

            break;
          case types.DS:
            break;
          default:
            return false;
        }
      }

      if (!sawReferral)
        return false;
    }

    return true;
  }

  verifyChain(keys, ds) {
    assert(Array.isArray(keys));
    assert(Array.isArray(ds));

    const [ksk, tag] = getKSK(keys);

    if (!ksk)
      return null;

    const map = new Map();

    map.set(tag, ksk);

    if (this.secure) {
      for (const key of getDowngraded(ksk, keys)) {
        const tag = key.data.keyTag();

        if (!map.has(tag))
          map.set(tag, key);
      }
    }

    for (const rr of ds) {
      assert(rr instanceof Record);
      assert(rr.type === types.DS);

      const rd = rr.data;

      // Never allow SHA1 for DS hashes.
      if (this.secure && rd.digestType === hashes.SHA1)
        continue;

      // Find the DS record with our tag.
      const key = map.get(rd.keyTag);

      if (!key)
        continue;

      // Recreate the DS record from our key.
      const ds = dnssec.createDS(key, rd.digestType);

      if (!ds)
        continue; // Failed to convert KSK (unknown alg).

      if (!ds.data.digest.equals(rd.digest))
        continue; // Mismatching DS.

      if (ds.data.algorithm !== rd.algorithm)
        continue; // Mismatching DS.

      return ksk;
    }

    return null;
  }

  verifyRecords(rrs, keys) {
    assert(Array.isArray(rrs));
    assert(Array.isArray(keys));

    const [sig, rrset] = splitSet(rrs);

    if (!sig)
      return false;

    const key = findKey(keys, sig.data.keyTag);

    if (!key)
      return false; // Missing DNS Key.

    return this.verifySignature(sig, key, rrset);
  }

  verifyKey(key, hardened = false) {
    assert(key instanceof Record);
    assert(key.type === types.DNSKEY);
    assert(typeof hardened === 'boolean');

    const kd = key.data;

    if (!this.isValidAlg(kd.algorithm))
      return false; // Invalid Algorithm.

    if (this.secure && this.isSHA1(kd.algorithm))
      return false; // Insecure Signature.

    if (this.isRSA(kd.algorithm)) {
      const bits = crypto.rsaBits(kd.publicKey);

      if (bits < this.minBits || bits > this.maxBits)
        return false; // Insecure Signature.

      if (hardened && bits < this.strongBits)
        return false; // Insecure Signature.
    }

    return true;
  }

  verifySignature(sig, key, rrset) {
    assert(sig instanceof Record);
    assert(sig.type === types.RRSIG);
    assert(key instanceof Record);
    assert(key.type === types.DNSKEY);
    assert(Array.isArray(rrset));

    if (rrset.length === 0)
      return false;

    if (!this.verifyKey(key))
      return false;

    return dnssec.verify(sig, key, rrset);
  }

  verifyKeys(zone, ds) {
    assert(zone instanceof Zone);

    const ksk = this.verifyChain(zone.keys, ds);

    if (!ksk)
      return false;

    const [sig, rrset] = splitSet(zone.keys);

    if (!sig)
      return false;

    return this.verifySignature(sig, ksk, rrset);
  }

  isValidAlg(algorithm) {
    assert((algorithm & 0xff) === algorithm);

    switch (algorithm) {
      case algs.RSASHA1:
      case algs.RSASHA1NSEC3SHA1:
      case algs.RSASHA256:
      case algs.RSASHA512:
      case algs.ECDSAP256SHA256:
      case algs.ECDSAP384SHA384:
      case algs.ED25519:
      case algs.ED448:
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

    let ds = await this._lookup(stub, name, types.DS, []);

    try {
      target.claim = await this._lookup(stub, name, types.TXT, []);
    } catch (e) {
      if (!estimate)
        throw e;
    }

    target.keys = await this._lookup(stub, name, types.DNSKEY, ds);

    zones.push(target);

    for (let i = 1; i <= labels.length; i++) {
      let parent = '.';

      if (i < labels.length)
        parent = util.from(name, labels, i);

      const zone = new Zone();
      zone.referral = ds;

      if (parent === '.')
        ds = this.anchors;
      else
        ds = await this._lookup(stub, parent, types.DS, []);

      zone.keys = await this._lookup(stub, parent, types.DNSKEY, ds);
      zones.push(zone);
    }

    zones.reverse();

    const proof = new this.Proof();
    proof.zones = zones;
    proof.canonical();

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

  async _lookup(stub, name, type, ds) {
    assert(stub instanceof this.Resolver);
    assert(typeof name === 'string');
    assert((type & 0xffff) === type);
    assert(Array.isArray(ds));

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

    const result = this.filterSignatures(rrs, type, ds);

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

  filterSignatures(answer, type, ds) {
    assert(Array.isArray(answer));
    assert((type & 0xffff) === type);
    assert(Array.isArray(ds));

    const dsSet = toDSSet(ds);
    const keyMap = toKeyMap(answer);
    const revSet = toRevSet(answer);
    const now = util.now();
    const rrs = [];

    let sig = null;

    for (const rr of answer) {
      assert(rr instanceof Record);

      if (rr.type === types.RRSIG) {
        const rd = rr.data;

        if (rd.typeCovered !== type)
          continue;

        if (!this.isValidAlg(rd.algorithm))
          continue;

        // Ignore old signatures.
        if (!rd.validityPeriod(now))
          continue;

        // Ignore SHA1 if secure.
        if (this.secure && this.isSHA1(rd.algorithm))
          continue;

        if (type === types.DNSKEY) {
          const key = keyMap.get(rd.keyTag);

          // Don't include revocation sigs.
          if (key && (key.data.flags & keyFlags.REVOKE))
            continue;

          // Don't include sigs from revoked keys.
          if (revSet.has(rd.keyTag))
            continue;
        }

        if (sig) {
          const sd = sig.data;

          if (type === types.DNSKEY) {
            // Prefer committed keys no matter what.
            if (!dsSet.has(sd.keyTag) && dsSet.has(rd.keyTag)) {
              sig = rr;
              continue;
            }

            if (dsSet.has(sd.keyTag) && !dsSet.has(rd.keyTag))
              continue;
          }

          // Prefer more secure algorithms.
          if (rd.algorithm < sd.algorithm)
            continue;

          // Prefer larger key sizes.
          if (this.isRSA(rd.algorithm) && this.isRSA(sd.algorithm)) {
            if (rd.signature.length < sd.signature.length)
              continue;
          }
        }

        sig = rr;

        continue;
      }

      rrs.push(rr);
    }

    if (!sig) {
      // Error at a higher level.
      return rrs;
    }

    rrs.push(sig);

    for (const rr of rrs)
      rr.ttl = sig.data.origTTL;

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

  getTarget() {
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

  toString() {
    let str = '';

    str += `;; DNSSEC OWNERSHIP PROOF: ${this.getTarget().toUpperCase()}\n`;
    str += `;; SIZE: ${this.getSize()}\n`;
    str += '\n';

    for (let i = 0; i < this.zones.length; i++) {
      const zone = this.zones[i];
      str += zone.toString() + '\n';
    }

    return str;
  }

  fromString(str) {
    assert(typeof str === 'string');

    const rrs = wire.fromZone(str);

    if (rrs.length === 0)
      throw new Error('No records found.');

    let zone = new Zone();
    let name = rrs[0].name;
    let state = types.DNSKEY;

    for (const rr of rrs) {
      let type = rr.type;

      if (type === types.RRSIG)
        type = rr.data.typeCovered;

      switch (state) {
        case types.DNSKEY:
          if (type === types.TXT) {
            state = types.TXT;
          } else if (!util.equal(rr.name, name)) {
            name = rr.name;
            state = types.DS;
          }
          break;
        case types.DS:
          if (type === types.DNSKEY) {
            if (zone.keys.length === 0)
              throw new Error('Switching zones without any keys.');

            if (zone.referral.length === 0)
              throw new Error('Switching zones without a referral.');

            this.zones.push(zone);

            zone = new Zone();
            state = types.DNSKEY;
          }
          break;
        case types.TXT:
          break;
        default:
          assert(false);
          break;
      }

      if (!util.equal(rr.name, name))
        throw new Error(`Invalid record name (${rr.name} != ${name}).`);

      if (type !== state) {
        const a = typeToString(type);
        const b = typeToString(state);
        throw new Error(`Invalid record type (${a} != ${b}).`);
      }

      switch (state) {
        case types.DNSKEY:
          zone.keys.push(rr);
          break;
        case types.DS:
          zone.referral.push(rr);
          break;
        case types.TXT:
          zone.claim.push(rr);
          break;
        default:
          assert(false);
          break;
      }
    }

    if (zone.keys.length === 0)
      throw new Error('Final zone has no keys.');

    if (zone.referral.length > 0)
      throw new Error('Final zone has unexpected referrals.');

    this.zones.push(zone);

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
    this.referral = [];
    this.claim = [];
  }

  get body() {
    return this.referral.length > 0
      ? this.referral
      : this.claim;
  }

  getTarget() {
    if (this.keys.length === 0)
      return '.';

    return this.keys[0].name.toLowerCase();
  }

  *records() {
    for (const rr of this.keys)
      yield rr;

    for (const rr of this.referral)
      yield rr;

    for (const rr of this.claim)
      yield rr;
  }

  inject(msg) {
    assert(msg instanceof this.constructor);
    this.keys = msg.keys.slice();
    this.referral = msg.referral.slice();
    this.claim = msg.claim.slice();
    return this;
  }

  deepClone() {
    const msg = new this.constructor();
    return msg.decode(this.encode());
  }

  canonical() {
    for (const rr of this.keys)
      rr.canonical();

    for (const rr of this.referral)
      rr.canonical();

    for (const rr of this.claim)
      rr.canonical();

    return this;
  }

  getSize(map) {
    let size = 1;

    for (const rr of this.keys)
      size += rr.getSize(map);

    size += 1;

    for (const rr of this.referral)
      size += rr.getSize(map);

    size += 1;

    for (const rr of this.claim)
      size += rr.getSize(map);

    return size;
  }

  write(bw, map) {
    bw.writeU8(this.keys.length);

    for (const rr of this.keys)
      rr.write(bw, map);

    bw.writeU8(this.referral.length);

    for (const rr of this.referral)
      rr.write(bw, map);

    bw.writeU8(this.claim.length);

    for (const rr of this.claim)
      rr.write(bw, map);

    return this;
  }

  read(br) {
    const rrCount = br.readU8();

    for (let i = 0; i < rrCount; i++) {
      const rr = readRecord(br, types.DNSKEY);
      this.keys.push(rr);
    }

    const dsCount = br.readU8();

    for (let i = 0; i < dsCount; i++) {
      const rr = readRecord(br, types.DS);
      this.referral.push(rr);
    }

    const claimCount = br.readU8();

    for (let i = 0; i < claimCount; i++) {
      const rr = readRecord(br, types.TXT);
      this.claim.push(rr);
    }

    return this;
  }

  toString() {
    let str = '';

    str += ';;\n';
    str += `;; ZONE: ${this.getTarget().toUpperCase()}\n`;
    str += ';;\n';

    str += '; KEYS:\n';

    for (const rr of this.keys)
      str += rr.toString() + '\n';

    str += '\n';

    str += this.claim.length > 0
      ? '; CLAIM:\n'
      : '; REFERRAL:\n';

    for (const rr of this.body)
      str += rr.toString() + '\n';

    return str;
  }

  getJSON() {
    return {
      keys: this.keys.map(rr => rr.toJSON()),
      referral: this.referral.map(rr => rr.toJSON()),
      claim: this.claim.map(rr => rr.toJSON())
    };
  }

  fromJSON(json) {
    assert(json && typeof json === 'object');
    assert(Array.isArray(json.keys));
    assert(Array.isArray(json.referral));

    for (const rr of json.keys)
      this.keys.push(Record.fromJSON(rr));

    for (const rr of json.referral)
      this.referral.push(Record.fromJSON(rr));

    for (const rr of json.claim)
      this.claim.push(Record.fromJSON(rr));

    return this;
  }
}

/*
 * Static
 */

Ownership.rootAnchors = rootAnchors;
Ownership.Proof = Proof;
Ownership.OwnershipProof = Proof;
Ownership.Zone = Zone;

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

function splitSet(rrs) {
  assert(Array.isArray(rrs));

  const rrset = [];

  let sig = null;

  for (const rr of rrs) {
    assert(rr instanceof Record);

    if (rr.type === types.RRSIG) {
      sig = rr;
      continue;
    }

    rrset.push(rr);
  }

  if (!sig || rrset.length === 0)
    return [null, null];

  return [sig, rrset];
}

function getSig(rrs) {
  assert(Array.isArray(rrs));

  for (const rr of rrs) {
    assert(rr instanceof Record);

    if (rr.type !== types.RRSIG)
      continue;

    return rr;
  }

  return null;
}

function findKey(rrs, tag) {
  assert(Array.isArray(rrs));
  assert((tag & 0xffff) === tag);

  for (const rr of rrs) {
    assert(rr instanceof Record);

    if (rr.type !== types.DNSKEY)
      continue;

    const rd = rr.data;

    if (rd.keyTag() !== tag)
      continue;

    // Explanation: someone could publish
    // a revocation sig. We pay no attention
    // to revocations normally. Why? Because
    // DNSSEC revocation doesn't truly revoke
    // anything. An attacker can still publish
    // old states. However, if someone _does_
    // publish a revocation sig for a DNSKEY
    // rrset, we should probably ignore it,
    // even though revocation keys typically
    // don't have DS records, and this should
    // fail at a higher level anyway.
    if (rd.flags & keyFlags.REVOKE)
      continue;

    return rr;
  }

  return null;
}

function getKSK(rrs) {
  assert(Array.isArray(rrs));

  const sig = getSig(rrs);

  if (!sig)
    return [null, null];

  const tag = sig.data.keyTag;
  const key = findKey(rrs, tag);

  return [key, tag];
}

function getDowngraded(ksk, rrs) {
  assert(ksk instanceof Record);
  assert(ksk.type === types.DNSKEY);
  assert(Array.isArray(rrs));

  const kd = ksk.data;
  const keys = [];

  if (kd.algorithm !== algs.RSASHA256
      && kd.algorithm !== algs.RSASHA512) {
    return keys;
  }

  for (const rr of rrs) {
    assert(rr instanceof Record);

    if (rr.type === types.RRSIG)
      continue;

    if (rr.type !== types.DNSKEY)
      continue;

    const rd = rr.data;

    if (rd.algorithm !== algs.RSASHA1
        && rd.algorithm !== algs.RSASHA1NSEC3SHA1) {
      continue;
    }

    if (rd.flags & keyFlags.REVOKE)
      continue;

    if (!rd.publicKey.equals(kd.publicKey))
      continue;

    keys.push(rr);
  }

  return keys;
}

function extractKey(rrs, keys) {
  assert(Array.isArray(rrs));
  assert(Array.isArray(keys));

  const sig = getSig(rrs);

  if (!sig)
    return null;

  const key = findKey(keys, sig.data.keyTag);

  if (!key)
    return null;

  return key;
}

function toKeyMap(rrs) {
  assert(Array.isArray(rrs));

  const map = new Map();

  for (const rr of rrs) {
    assert(rr instanceof Record);

    if (rr.type !== types.DNSKEY)
      continue;

    const tag = rr.data.keyTag();

    if (!map.has(tag))
      map.set(tag, rr);
  }

  return map;
}

function toRevSet(rrs) {
  assert(Array.isArray(rrs));

  const set = new Set();

  for (const rr of rrs) {
    assert(rr instanceof Record);

    if (rr.type !== types.DNSKEY)
      continue;

    if (!(rr.data.flags & keyFlags.REVOKE))
      continue;

    set.add(rr.data.revTag());
  }

  return set;
}

function toDSSet(rrs) {
  assert(Array.isArray(rrs));

  const set = new Set();

  for (const rr of rrs) {
    assert(rr instanceof Record);

    if (rr.type !== types.DS)
      continue;

    set.add(rr.data.keyTag);
  }

  return set;
}

/*
 * Expose
 */

module.exports = Ownership;
