/*!
 * dnssec.js - DNSSEC for bns
 * Copyright (c) 2018, Christopher Jeffrey (MIT License).
 * https://github.com/chjj/bns
 *
 * Parts of this software are based on miekg/dns and golang/go:
 *   https://github.com/miekg/dns/blob/master/dnssec.go
 *
 * Parts of this software are based on solvere:
 *   https://github.com/rolandshoemaker/solvere
 */

'use strict';

const assert = require('bsert');
const bio = require('bufio');
const constants = require('./constants');
const crypto = require('./internal/crypto');
const encoding = require('./encoding');
const keys = require('./internal/keys');
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
  classes,
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
  DNSKEYRecord,
  RRSIGRecord
} = wire;

/*
 * Constants
 */

const algToHash = {
  [algs.RSAMD5]: crypto.md5, // Deprecated in RFC 6725
  [algs.DSA]: crypto.sha1,
  [algs.RSASHA1]: crypto.sha1,
  [algs.DSANSEC3SHA1]: crypto.sha1,
  [algs.RSASHA1NSEC3SHA1]: crypto.sha1,
  [algs.RSASHA256]: crypto.sha256,
  [algs.ECDSAP256SHA256]: crypto.sha256,
  [algs.ECDSAP384SHA384]: crypto.sha384,
  [algs.RSASHA512]: crypto.sha512,
  [algs.ED25519]: {},
  [algs.ED448]: {}
};

const hashToHash = {
  [hashes.SHA1]: crypto.sha1,
  [hashes.SHA256]: crypto.sha256,
  [hashes.GOST94]: crypto.gost94,
  [hashes.SHA384]: crypto.sha384,
  [hashes.SHA512]: crypto.sha512
};

/*
 * DNSSEC
 */

const dnssec = exports;

dnssec.filename = keys.filename;
dnssec.privFile = keys.privFile;
dnssec.pubFile = keys.pubFile;

dnssec.createPrivate = keys.createPrivate;
dnssec.createPrivateAsync = keys.createPrivateAsync;
dnssec.createPublic = keys.createPublic;
dnssec.encodePrivate = keys.encodePrivate;
dnssec.decodePrivate = keys.decodePrivate;

dnssec.readPrivate = keys.readPrivate;
dnssec.readPrivateAsync = keys.readPrivateAsync;
dnssec.readPublic = keys.readPublic;
dnssec.readPublicAsync = keys.readPublicAsync;
dnssec.writeKeys = keys.writeKeys;
dnssec.writeKeysAsync = keys.writeKeysAsync;
dnssec.writePrivate = keys.writePrivate;
dnssec.writePrivateAsync = keys.writePrivateAsync;
dnssec.writePublic = keys.writePublic;
dnssec.writePublicAsync = keys.writePublicAsync;

dnssec.makeKey = function makeKey(name, algorithm, priv, flags) {
  const pub = dnssec.createPublic(algorithm, priv);
  return dnssec.createKey(name, algorithm, pub, flags);
};

dnssec.createKey = function createKey(name, algorithm, publicKey, flags) {
  if (flags == null)
    flags = keyFlags.ZONE;

  assert(typeof name === 'string');
  assert(util.isFQDN(name));
  assert((algorithm & 0xff) === algorithm);
  assert(Buffer.isBuffer(publicKey));
  assert((flags & 0xffff) === flags);

  const rr = new Record();
  const rd = new DNSKEYRecord();

  rr.name = name;
  rr.class = classes.IN;
  rr.type = types.DNSKEY;
  rr.ttl = 172800;
  rr.data = rd;

  rd.flags = flags;
  rd.protocol = 3;
  rd.algorithm = algorithm;
  rd.publicKey = publicKey;

  return rr;
};

dnssec.createDS = function createDS(key, digestType) {
  if (digestType == null)
    digestType = hashes.SHA256;

  assert(key instanceof Record);
  assert(key.type === types.DNSKEY);
  assert((digestType & 0xff) === digestType);

  const kd = key.data;
  const hash = hashToHash[digestType];

  if (!hash)
    return null;

  const raw = kd.encode();
  const keyTag = kd.keyTag(raw);
  const owner = packName(key.name);

  const rr = new Record();
  const rd = new DSRecord();

  rr.name = key.name;
  rr.class = key.class;
  rr.type = types.DS;
  rr.ttl = key.ttl;
  rr.data = rd;

  rd.algorithm = kd.algorithm;
  rd.digestType = digestType;
  rd.keyTag = keyTag;
  rd.digest = hash.multi(owner, raw);

  return rr;
};

dnssec.signType = function signType(rrs, type, key, priv, lifespan) {
  assert(Array.isArray(rrs));
  assert((type & 0xffff) === type);

  const rrset = extractSet(rrs, '', type);

  if (rrset.length === 0)
    return rrs;

  const sig = dnssec.sign(key, priv, rrset, lifespan);

  rrs.push(sig);

  return rrs;
};

dnssec.sign = function sign(key, priv, rrset, lifespan) {
  if (lifespan == null)
    lifespan = 365 * 24 * 60 * 60;

  assert(key instanceof Record);
  assert(key.type === types.DNSKEY);
  assert(Array.isArray(rrset));
  assert((lifespan >>> 0) === lifespan);

  const rr = new Record();
  const rd = new RRSIGRecord();

  rr.name = key.name;
  rr.ttl = key.ttl;
  rr.class = key.class;
  rr.type = types.RRSIG;
  rr.data = rd;

  rd.keyTag = key.data.keyTag();
  rd.signerName = key.name;
  rd.algorithm = key.data.algorithm;
  rd.inception = util.now() - (24 * 60 * 60);
  rd.expiration = util.now() + lifespan;

  return dnssec.signRRSIG(rr, priv, rrset);
};

dnssec.signRRSIG = function signRRSIG(sig, priv, rrset) {
  assert(sig instanceof Record);
  assert(sig.type === types.RRSIG);
  assert(Buffer.isBuffer(priv));
  assert(Array.isArray(rrset));

  const sd = sig.data;

  if (!isRRSet(rrset))
    throw new Error('Invalid RR set.');

  if (sd.keyTag === 0 || sd.signerName.length === 0 || sd.algorithm === 0)
    throw new Error('Invalid signature record.');

  sig.type = types.RRSIG;
  sig.name = rrset[0].name;
  sig.class = rrset[0].class;
  sig.data = sd;

  if (sd.origTTL === 0)
    sd.origTTL = rrset[0].ttl;

  sd.typeCovered = rrset[0].type;
  sd.labels = countLabels(rrset[0].name);

  if (rrset[0].name[0] === '*')
    sd.labels -= 1;

  const data = dnssec.signatureHash(sig, rrset);

  if (!data)
    throw new Error('Bad number of labels.');

  sd.signature = dnssec.signData(priv, data, sd.algorithm);

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
      return crypto.signDSA(hash, data, keybuf);
    case algs.RSAMD5:
    case algs.RSASHA1:
    case algs.RSASHA1NSEC3SHA1:
    case algs.RSASHA256:
    case algs.RSASHA512:
      return crypto.signRSA(hash, data, keybuf);
    case algs.ECDSAP256SHA256:
      return crypto.signP256(hash, data, keybuf);
    case algs.ECDSAP384SHA384:
      return crypto.signP384(hash, data, keybuf);
    case algs.ED25519:
      return crypto.signED25519(data, keybuf);
    case algs.ED448:
      return crypto.signED448(data, keybuf);
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

  if (!util.equal(s.signerName, key.name))
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
  assert(sig.type === types.RRSIG || sig.type === types.SIG);
  assert(key instanceof Record);
  assert(key.type === types.DNSKEY || key.type === types.KEY);
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
      return crypto.verifyDSA(hash, data, sigbuf, keybuf);
    case algs.RSAMD5:
    case algs.RSASHA1:
    case algs.RSASHA1NSEC3SHA1:
    case algs.RSASHA256:
    case algs.RSASHA512:
      return crypto.verifyRSA(hash, data, sigbuf, keybuf);
    case algs.ECDSAP256SHA256:
      return crypto.verifyP256(hash, data, sigbuf, keybuf);
    case algs.ECDSAP384SHA384:
      return crypto.verifyP384(hash, data, sigbuf, keybuf);
    case algs.ED25519:
      return crypto.verifyED25519(data, sigbuf, keybuf);
    case algs.ED448:
      return crypto.verifyED448(data, sigbuf, keybuf);
  }

  return false; // Unknown algorithm
};

dnssec.signatureHash = function signatureHash(sig, rrset) {
  assert(sig instanceof Record);
  assert(sig.type === types.RRSIG);
  assert(Array.isArray(rrset));

  const sd = sig.data;
  const records = [];

  for (const item of rrset) {
    assert(item instanceof Record);

    const rr = item.deepClone();
    const labels = splitName(rr.name);

    // Server is using wildcards.
    if (labels.length > sd.labels) {
      const i = labels.length - sd.labels;
      const name = labels.slice(i).join('.');
      rr.name = `*.${name}.`;
    }

    // Invalid RR set.
    if (labels.length < sd.labels)
      return null;

    // Canonical TTL.
    rr.ttl = sd.origTTL;

    // Canonicalize all domain
    // names (see RFC 4034).
    rr.canonical();

    // Push for sorting.
    records.push(rr.encode());
  }

  records.sort(compare);

  const tbs = sd.toTBS();

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

    if (!(rd.flags & keyFlags.ZONE))
      continue;

    if (!util.equal(rr.name, name))
      continue;

    if (rd.flags & keyFlags.REVOKE)
      continue;

    kskMap.set(rd.keyTag(), rr);
  }

  const valid = new Map();

  for (const rr of ds) {
    assert(rr instanceof Record);
    assert(rr.type === types.DS);

    const rd = rr.data;
    const key = kskMap.get(rd.keyTag);

    if (!key)
      continue;

    const ds = dnssec.createDS(key, rd.digestType);

    if (!ds)
      continue; // Failed to convert KSK (unknown alg).

    if (!ds.data.digest.equals(rd.digest))
      return null; // Mismatching DS.

    if (ds.data.algorithm !== rd.algorithm)
      return null; // Mismatching algorithm.

    valid.set(rd.keyTag, key);

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

      if (!rd.validityPeriod())
        continue; // Invalid Signature Period

      sigs.push(rr);
      continue;
    }
  }

  if (keys.length === 0)
    return false; // No keys

  if (sigs.length === 0)
    return false; // No sigs

  for (const sig of sigs) {
    const sd = sig.data;
    const key = kskMap.get(sd.keyTag);
    assert(key);

    if (!dnssec.verify(sig, key, keys))
      return false; // Invalid Signature
  }

  return true;
};

dnssec.verifyMessage = function verifyMessage(msg, zskMap, revSet) {
  if (revSet == null)
    revSet = new Set();

  assert(msg instanceof Message);
  assert(zskMap instanceof Map);
  assert(revSet instanceof Set);

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

    if (util.hasType(section, types.NSEC))
      set.add(types.NSEC);

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

    const rd = rr.data;

    if (!rd.validityPeriod())
      continue; // Invalid Signature Period

    if (!set.has(rd.typeCovered))
      continue; // Useless

    if (revSet.has(rd.keyTag))
      continue; // Revoked signature.

    const key = zskMap.get(rd.keyTag);

    if (!key)
      continue; // Missing DNS Key

    const rrset = extractSet(section, rr.name, rd.typeCovered);

    if (rrset.length === 0)
      continue; // Missing Signed

    if (!dnssec.verify(rr, key, rrset))
      continue; // Invalid Signature

    set.delete(rd.typeCovered);
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

dnssec.stripSignatures = function stripSignatures(msg) {
  assert(msg instanceof Message);

  msg.answer = util.filterSet(msg.answer, types.RRSIG);
  msg.authority = util.filterSet(msg.authority, types.RRSIG);
  msg.additional = util.filterSet(msg.additional, types.RRSIG);

  return msg;
};

/*
 * Helpers
 */

function compare(a, b) {
  const [ao] = readName(a, 0, true);
  const [bo] = readName(b, 0, true);
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
