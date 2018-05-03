/*!
 * dnssec.js - DNSSEC for bns
 * Copyright (c) 2018, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bns
 *
 * Parts of this software are based on miekg/dns and golang/go:
 *   https://github.com/miekg/dns/blob/master/dnssec.go
 *
 * Parts of this software are based on solvere:
 *   https://github.com/rolandshoemaker/solvere
 */

'use strict';

const assert = require('assert');
const bio = require('bufio');
const constants = require('./constants');
const crypto = require('./crypto');
const encoding = require('./encoding');
const util = require('./util');
const wire = require('./wire');

const {
  readName,
  packName
} = encoding;

const {
  isRRSet,
  countLabels,
  splitName,
  extractSet
} = util;

const {
  types,
  keyFlags,
  algs,
  algsByVal,
  hashes,
  hashesByVal,
  algHashes
} = constants;

const {
  Message,
  Record,
  DSRecord,
  RRSIGRecord
} = wire;

/*
 * Constants
 */

const algToHash = {
  [algs.RSAMD5]: crypto.md5, // Deprecated in RFC 6725
  [algs.RSASHA1]: crypto.sha1,
  [algs.RSASHA1NSEC3SHA1]: crypto.sha1,
  [algs.RSASHA256]: crypto.sha256,
  [algs.ECDSAP256SHA256]: crypto.sha256,
  [algs.ECDSAP384SHA384]: crypto.sha384,
  [algs.RSASHA512]: crypto.sha512,
  [algs.ED25519]: crypto.sha256
};

const hashToHash = {
  [hashes.SHA1]: crypto.sha1,
  [hashes.SHA256]: crypto.sha256,
  [hashes.GOST94]: null,
  [hashes.SHA384]: crypto.sha384,
  [hashes.SHA512]: crypto.sha512
};

/*
 * DNSSEC
 */

const dnssec = exports;

dnssec.createDS = function createDS(dnskey, digestType) {
  assert(dnskey instanceof Record);
  assert(dnskey.type === types.DNSKEY);
  assert((digestType & 0xff) === digestType);

  const dk = dnskey.data; // DNSKEY
  const hash = hashToHash[digestType];

  if (!hash)
    return null;

  const raw = dk.encode();
  const keyTag = dk.keyTag(raw);
  const owner = packName(dnskey.name);

  const ctx = hash.hash();
  ctx.init();
  ctx.update(owner);
  ctx.update(raw);

  const rr = new Record();
  rr.name = dnskey.name;
  rr.class = dnskey.class;
  rr.type = types.DS;
  rr.ttl = dnskey.ttl;

  const ds = new DSRecord();
  ds.algorithm = dk.algorithm;
  ds.digestType = digestType;
  ds.keyTag = keyTag;
  ds.digest = ctx.final();

  rr.data = ds;

  return rr;
};

dnssec.signMessage = function signMessage(msg, name, key, priv, lifespan) {
  assert(msg instanceof Message);

  for (const section of msg.sections()) {
    const sigs = dnssec.signSection(section, name, key, priv, lifespan);
    for (const sig of sigs)
      section.push(sig);
  }

  return msg;
};

dnssec.signSection = function signSection(section, name, key, priv, lifespan) {
  assert(Array.isArray(section));

  const set = new Set();
  const sigs = [];

  for (const rr of section)
    set.add(rr.type);

  for (const type of set) {
    if (type === types.OPT
        || type === types.RRSIG
        || type === types.SIG) {
      continue;
    }

    const rrset = extractSet(section, name, type);

    if (rrset.length === 0)
      continue;

    const sig = dnssec.rrsign(key, priv, rrset, lifespan);
    sigs.push(sig);
  }

  return sigs;
};

dnssec.signType = function signType(section, type, key, priv, lifespan) {
  assert(Array.isArray(section));
  assert((type & 0xffff) === type);

  const rrset = extractSet(section, '', type);

  if (rrset.length === 0)
    return section;

  const sig = dnssec.rrsign(key, priv, rrset, lifespan);

  section.push(sig);

  return section;
};

dnssec.rrsign = function rrsign(key, priv, rrset, lifespan) {
  if (lifespan == null)
    lifespan = 14 * 24 * 60 * 60;

  assert(key instanceof Record);
  assert(key.type === types.DNSKEY);
  assert(Array.isArray(rrset));
  assert((lifespan >>> 0) === lifespan);

  const sig = new Record();
  const s = new RRSIGRecord();

  sig.name = key.name;
  sig.ttl = key.ttl;
  sig.class = key.class;
  sig.type = types.RRSIG;
  sig.data = s;

  s.keyTag = key.data.keyTag();
  s.signerName = key.name;
  s.algorithm = key.data.algorithm;
  s.inception = util.now() - lifespan;
  s.expiration = util.now() + lifespan;

  return dnssec.sign(sig, priv, rrset);
};

dnssec.sign = function sign(sig, priv, rrset) {
  assert(sig instanceof Record);
  assert(sig.type === types.RRSIG);
  assert(Buffer.isBuffer(priv));
  assert(Array.isArray(rrset));

  const s = sig.data; // RRSIG

  if (!isRRSet(rrset))
    throw new Error('Invalid RR set.');

  if (s.keyTag === 0 || s.signerName.length === 0 || s.algorithm === 0)
    throw new Error('Invalid signature record.');

  sig.type = types.RRSIG;
  sig.name = rrset[0].name;
  sig.class = rrset[0].class;
  sig.data = s;

  if (s.origTTL === 0)
    s.origTTL = rrset[0].ttl;

  s.typeCovered = rrset[0].type;
  s.labels = countLabels(rrset[0].name);

  if (rrset[0].name[0] === '*')
    s.labels -= 1;

  const data = dnssec.signatureHash(sig, rrset);

  if (!data)
    throw new Error('Bad number of labels.');

  s.signature = dnssec.signData(priv, data, s.algorithm);

  return sig;
};

dnssec.signData = function signData(priv, data, algorithm) {
  assert(Buffer.isBuffer(priv));
  assert(Buffer.isBuffer(data));
  assert((algorithm & 0xff) === algorithm);

  const keybuf = priv;
  const hash = algToHash[algorithm];

  if (!hash)
    throw new Error('Unknown hash algorithm.');

  switch (algorithm) {
    case algs.DSA:
    case algs.DSANSEC3SHA1:
      throw new Error('Unsupported public key algorithm.');
    case algs.RSAMD5:
    case algs.RSASHA1:
    case algs.RSASHA1NSEC3SHA1:
    case algs.RSASHA256:
    case algs.RSASHA512:
      return crypto.signRSA(hash, data, keybuf);
    case algs.ECDSAP256SHA256:
      return crypto.signECDSA('p256', hash, data, keybuf);
    case algs.ECDSAP384SHA384:
      return crypto.signECDSA('p384', hash, data, keybuf);
    case algs.ED25519:
      return crypto.signEDDSA('ed25519', hash, data, keybuf);
    case algs.ED448:
      throw new Error('Unsupported public key algorithm.');
  }

  throw new Error('Unknown public key algorithm.');
};

dnssec.verify = function verify(sig, key, rrset) {
  assert(sig instanceof Record);
  assert(sig.type === types.RRSIG);
  assert(key instanceof Record);
  assert(key.type === types.DNSKEY);
  assert(Array.isArray(rrset));

  const s = sig.data; // RRSIG
  const k = key.data; // DNSKEY

  if (!isRRSet(rrset))
    return false; // Invalid RR set

  if (s.keyTag !== k.keyTag())
    return false; // Key tag mismatch

  if (sig.class !== key.class)
    return false; // Class mismatch

  if (s.algorithm !== k.algorithm)
    return false; // Algorithm mismatch

  if (s.signerName.toLowerCase() !== key.name.toLowerCase())
    return false; // Name mismatch

  if (k.protocol !== 3)
    return false; // Invalid protocol

  if (rrset[0].class !== sig.class)
    return false; // Class mismatch

  if (rrset[0].type !== s.typeCovered)
    return false; // Type mismatch

  const data = dnssec.signatureHash(sig, rrset);

  if (!data)
    return false;

  return dnssec.verifyData(sig, key, data, s.algorithm);
};

dnssec.verifyData = function verifyData(sig, key, data, algorithm) {
  assert(sig instanceof Record);
  assert(sig.type === types.RRSIG);
  assert(key instanceof Record);
  assert(key.type === types.DNSKEY);
  assert(Buffer.isBuffer(data));
  assert((algorithm & 0xff) === algorithm);

  const keybuf = key.data.publicKey;
  const sigbuf = sig.data.signature;
  const hash = algToHash[algorithm];

  if (!hash)
    return false;

  switch (algorithm) {
    case algs.DSA:
    case algs.DSANSEC3SHA1:
      return false;
    case algs.RSAMD5:
    case algs.RSASHA1:
    case algs.RSASHA1NSEC3SHA1:
    case algs.RSASHA256:
    case algs.RSASHA512:
      return crypto.verifyRSA(hash, data, sigbuf, keybuf);
    case algs.ECDSAP256SHA256:
      return crypto.verifyECDSA('p256', hash, data, sigbuf, keybuf);
    case algs.ECDSAP384SHA384:
      return crypto.verifyECDSA('p384', hash, data, sigbuf, keybuf);
    case algs.ED25519:
      return crypto.verifyEDDSA('ed25519', hash, data, sigbuf, keybuf);
    case algs.ED448:
      return false;
  }

  return false; // Unknown algorithm
};

dnssec.signatureHash = function signatureHash(sig, rrset) {
  assert(sig instanceof Record);
  assert(sig.type === types.RRSIG);
  assert(Array.isArray(rrset));

  const s = sig.data; // RRSIG
  const records = [];

  for (const item of rrset) {
    assert(item instanceof Record);

    const rr = item.deepClone();
    const labels = splitName(rr.name);

    // Server is using wildcards.
    if (labels.length > s.labels) {
      const i = labels.length - s.labels;
      const name = labels.slice(i).join('.');
      rr.name = `*.${name}.`;
    }

    // Invalid RR set.
    if (labels.length < s.labels)
      return null;

    // Canonical TTL.
    rr.ttl = s.origTTL;

    // Canonicalize all domain
    // names (see RFC 4034).
    rr.canonical();

    // Push for sorting.
    records.push(rr.encode());
  }

  records.sort(compare);

  const tbs = s.toTBS();

  let size = 0;

  size += tbs.length;

  for (let i = 0; i < records.length; i++) {
    const raw = records[i];

    if (i > 0 && raw.equals(records[i - 1]))
      continue;

    size += raw.length;
  }

  const bw = bio.write(size);

  bw.writeBytes(tbs);

  for (let i = 0; i < records.length; i++) {
    const raw = records[i];

    if (i > 0 && raw.equals(records[i - 1]))
      continue;

    bw.writeBytes(raw);
  }

  return bw.render();
};

dnssec.verifyDS = function verifyDS(msg, ds, name) {
  assert(msg instanceof Message);
  assert(Array.isArray(ds));
  assert(typeof name === 'string');

  if (ds.length === 0)
    return false;

  const kskMap = new Map();

  for (const rr of msg.answer) {
    if (rr.type !== types.DNSKEY)
      continue;

    const rd = rr.data;

    if (rd.flags & keyFlags.REVOKE)
      continue;

    if (!(rd.flags & keyFlags.ZONE))
      continue;

    if (!util.equal(rr.name, name))
      continue;

    if (rd.flags & keyFlags.SEP)
      kskMap.set(rd.keyTag(), rr);
  }

  const valid = new Map();

  for (const rr of ds) {
    assert(rr instanceof Record);
    assert(rr.type === types.DS);

    const rd = rr.data;
    const dnskey = kskMap.get(rd.keyTag);

    if (!dnskey)
      continue;

    const ds = dnssec.createDS(dnskey, rd.digestType);

    if (!ds)
      continue; // Failed to convert KSK (unknown alg).

    if (!ds.data.digest.equals(rd.digest))
      return null; // Mismatching DS.

    valid.set(rd.keyTag, dnskey);

    continue;
  }

  if (valid.size === 0)
    return null;

  return valid;
};

dnssec.verifyZSK = function verifyZSK(msg, kskMap, name) {
  assert(msg instanceof Message);
  assert(kskMap instanceof Map);
  assert(typeof name === 'string');

  if (msg.answer.length === 0)
    return false; // No keys

  if (kskMap.size === 0)
    return false; // No keys

  const keys = [];
  const sigs = [];

  for (const rr of msg.answer) {
    const rd = rr.data;

    if (rr.type === types.DNSKEY) {
      if (!util.equal(rr.name, name))
        continue;
      keys.push(rr);
      continue;
    }

    if (rr.type === types.RRSIG) {
      if (rd.typeCovered !== types.DNSKEY)
        continue;

      if (!util.equal(rr.name, name))
        continue;

      if (!kskMap.has(rd.keyTag))
        continue;

      sigs.push(rr);
      continue;
    }
  }

  if (keys.length === 0)
    return false; // No keys

  if (sigs.length === 0)
    return false; // No sigs

  for (const sig of sigs) {
    const s = sig.data;
    const dnskey = kskMap.get(s.keyTag);

    if (!dnskey)
      return false; // Missing DNS Key

    if (!s.validityPeriod())
      return false; // Invalid Signature Period

    if (!dnssec.verify(sig, dnskey, keys))
      return false; // Invalid Signature
  }

  return true;
};

dnssec.verifyRRSIG = function verifyRRSIG(msg, zskMap) {
  assert(msg instanceof Message);
  assert(zskMap instanceof Map);

  const isAnswer = msg.isAnswer();
  const isReferral = msg.isReferral();

  if (!isAnswer && !isReferral)
    return true;

  const set = new Set();

  let section = msg.answer;

  if (isReferral) {
    section = msg.authority;

    // We need a signed DS, NSEC3,
    // or NS record for a referral.
    if (util.hasType(section, types.DS))
      set.add(types.DS);

    if (util.hasType(section, types.NSEC3))
      set.add(types.NSEC3);
  }

  // If we don't have any specific
  // types to look for, verify
  // everything in the section.
  if (set.size === 0) {
    for (const rr of section) {
      // No signed signatures.
      if (rr.type === types.RRSIG
          || rr.type === types.SIG) {
        continue;
      }

      // No special records.
      if (rr.type === types.OPT
          || rr.type === types.TSIG) {
        continue;
      }

      set.add(rr.type);
    }
  }

  // Some kind of error.
  // Verify elsewhere.
  if (set.size === 0)
    return true;

  for (const rr of section) {
    if (rr.type !== types.RRSIG)
      continue;

    const s = rr.data;
    const dnskey = zskMap.get(s.keyTag);

    if (!dnskey)
      continue; // Missing DNS Key

    if (!s.validityPeriod())
      continue; // Invalid Signature Period

    const rrset = extractSet(section, rr.name, s.typeCovered);

    if (rrset.length === 0)
      continue; // Missing Signed

    if (!dnssec.verify(rr, dnskey, rrset))
      continue; // Invalid Signature

    set.delete(s.typeCovered);
  }

  if (set.size !== 0)
    return false; // Unsigned Data

  return true;
};

dnssec.filterMessage = function filterMessage(msg, type) {
  assert(msg instanceof Message);
  assert((type & 0xffff) === type);

  msg.answer = dnssec.filterSection(msg.answer, type);
  msg.authority = dnssec.filterSection(msg.authority, type);
  msg.additional = dnssec.filterSection(msg.additional, type);

  return msg;
};

dnssec.filterSection = function filterSection(section, type) {
  assert(Array.isArray(section));
  assert((type & 0xffff) === type);

  const filtered = [];

  for (const rr of section) {
    assert(rr instanceof Record);

    switch (rr.type) {
      case types.DS:
      case types.DLV:
      case types.DNSKEY:
      case types.RRSIG:
      case types.NXT:
      case types.NSEC:
      case types.NSEC3:
      case types.NSEC3PARAM:
        if (type !== rr.type)
          break;
        // fall through
      default:
        filtered.push(rr);
        break;
    }
  }

  return filtered;
};

/*
 * Helpers
 */

function compare(a, b) {
  const [ao] = readName(a, 0);
  const [bo] = readName(b, 0);
  const ab = a.slice(ao + 10);
  const bb = b.slice(bo + 10);
  return ab.compare(bb);
}

/*
 * Expose
 */

dnssec.keyFlags = keyFlags;
dnssec.algs = algs;
dnssec.algsByVal = algsByVal;
dnssec.hashes = hashes;
dnssec.hashesByVal = hashesByVal;
dnssec.algHashes = algHashes;
dnssec.algToHash = algToHash;
dnssec.hashToHash = hashToHash;
