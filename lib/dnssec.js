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

const bio = require('bufio');
const encoding = require('./encoding');
const util = require('./util');
const wire = require('./wire');
const crypto = require('./crypto');

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
  Record,
  DSRecord
} = wire;

const dnssec = exports;

// DNSKEY flag values.
const flags = {
  SEP: 1,
  REVOKE: 1 << 7,
  ZONE: 1 << 8
};

// DNSSEC encryption algorithm codes.
const algs = {
  // _: 0,
  RSAMD5: 1,
  DH: 2,
  DSA: 3,
  // _: 4,
  RSASHA1: 5,
  DSANSEC3SHA1: 6,
  RSASHA1NSEC3SHA1: 7,
  RSASHA256: 8,
  // _: 9,
  RSASHA512: 10,
  // _: 11,
  ECCGOST: 12,
  ECDSAP256SHA256: 13,
  ECDSAP384SHA384: 14,
  ED25519: 15,
  ED448: 16,
  INDIRECT: 252,
  PRIVATEDNS: 253, // Private (experimental keys)
  PRIVATEOID: 254
};

const algsByVal = {
  [algs.RSAMD5]: 'RSAMD5',
  [algs.DH]: 'DH',
  [algs.DSA]: 'DSA',
  [algs.RSASHA1]: 'RSASHA1',
  [algs.DSANSEC3SHA1]: 'DSA-NSEC3-SHA1',
  [algs.RSASHA1NSEC3SHA1]: 'RSASHA1-NSEC3-SHA1',
  [algs.RSASHA256]: 'RSASHA256',
  [algs.RSASHA512]: 'RSASHA512',
  [algs.ECCGOST]: 'ECC-GOST',
  [algs.ECDSAP256SHA256]: 'ECDSAP256SHA256',
  [algs.ECDSAP384SHA384]: 'ECDSAP384SHA384',
  [algs.ED25519]: 'ED25519',
  [algs.ED448]: 'ED448',
  [algs.INDIRECT]: 'INDIRECT',
  [algs.PRIVATEDNS]: 'PRIVATEDNS',
  [algs.PRIVATEOID]: 'PRIVATEOID'
};

// DNSSEC hashing algorithm codes.
const hashes = {
  // _: 0,
  SHA1: 1, // RFC 4034
  SHA256: 2, // RFC 4509
  GOST94: 3, // RFC 5933
  SHA384: 4, // Experimental
  SHA512: 5 // Experimental
};

const hashByVal = {
  [hashes.SHA1]: 'SHA1',
  [hashes.SHA256]: 'SHA256',
  [hashes.GOST94]: 'GOST94',
  [hashes.SHA384]: 'SHA384',
  [hashes.SHA512]: 'SHA512'
};

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

dnssec.createDS = function createDS(dnskey, digestType) {
  const dk = dnskey.data; // DNSKEY
  const hash = hashToHash[digestType];

  if (!hash)
    return null;

  const raw = dk.toRaw();
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

dnssec.sign = function sign(sig, priv, rrset) {
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

  s.signature = dnssec.signature(priv, data, s.algorithm);

  return sig;
};

dnssec.signature = function signature(priv, data, algorithm) {
  const keybuf = priv;
  const hash = algToHash[algorithm];

  if (hash === undefined)
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
    return null;

  return dnssec._verify(sig, key, data, s.algorithm);
};

dnssec._verify = function _verify(sig, key, data, algorithm) {
  const keybuf = key.data.publicKey;
  const sigbuf = sig.data.signature;
  const hash = algToHash[algorithm];

  if (hash === undefined)
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
  const s = sig.data; // RRSIG
  const records = [];

  for (const rr of rrset) {
    const r = rr.clone();

    r.name = r.name.toLowerCase();
    r.ttl = s.origTTL;
    r.data = r.data.clone();

    const labels = splitName(r.name);

    if (labels.length > s.labels) {
      // Wildcard
      const i = labels.length - s.labels;
      const name = labels.slice(i).join('.');
      r.name = `*.${name}.`;
    }

    if (labels.length < s.labels)
      return null;

    const x = r.data;

    switch (r.type) {
      case types.NS:
        x.ns = x.ns.toLowerCase();
        break;
      case types.MD:
        x.md = x.md.toLowerCase();
        break;
      case types.MF:
        x.mf = x.mf.toLowerCase();
        break;
      case types.CNAME:
        x.target = x.target.toLowerCase();
        break;
      case types.SOA:
        x.ns = x.ns.toLowerCase();
        x.mbox = x.mbox.toLowerCase();
        break;
      case types.MB:
        x.mb = x.mb.toLowerCase();
        break;
      case types.MG:
        x.mg = x.mg.toLowerCase();
        break;
      case types.MR:
        x.mr = x.mr.toLowerCase();
        break;
      case types.PTR:
        x.ptr = x.ptr.toLowerCase();
        break;
      case types.MINFO:
        x.rmail = x.rmail.toLowerCase();
        x.email = x.email.toLowerCase();
        break;
      case types.MX:
        x.mx = x.mx.toLowerCase();
        break;
      case types.RP:
        x.mbox = x.mbox.toLowerCase();
        x.txt = x.txt.toLowerCase();
        break;
      case types.AFSDB:
        x.hostname = x.hostname.toLowerCase();
        break;
      case types.SIG:
      case types.RRSIG:
        x.signerName = x.signerName.toLowerCase();
        break;
      case types.PX:
        x.map822 = x.map822.toLowerCase();
        x.mapx400 = x.mapx400.toLowerCase();
        break;
      case types.NAPTR:
        x.replacement = x.replacement.toLowerCase();
        break;
      case types.KX:
        x.exchanger = x.exchanger.toLowerCase();
        break;
      case types.SRV:
        x.target = x.target.toLowerCase();
        break;
      case types.DNAME:
        x.target = x.target.toLowerCase();
        break;
    }

    records.push(r.toRaw());
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

dnssec.verifyDS = function verifyDS(keyMap, ds) {
  for (const rr of ds) {
    const rd = rr.data;
    const dnskey = keyMap.get(rd.keyTag);

    if (!dnskey)
      continue;

    const ds = dnssec.createDS(dnskey, rd.digestType);

    if (!ds)
      return false; // Failed to convert KSK

    if (!ds.data.digest.equals(rd.digest))
      return false; // Mismatching DS

    return true;
  }

  return false;
};

dnssec.verifyRRSIG = function verifyRRSIG(msg, keyMap) {
  const sections = [msg.answer];

  if (msg.aa)
    sections.push(msg.authority);

  for (const section of sections) {
    if (section.length === 0)
      continue;

    const set = new Set();

    for (const rr of section) {
      if (rr.type === types.RRSIG)
        continue;

      set.add(rr.type);
    }

    const sigs = extractSet(section, '', types.RRSIG);

    if (sigs.length === 0)
      return false; // No Signatures

    for (const sig of sigs) {
      const s = sig.data;
      const rest = extractSet(section, sig.name, s.typeCovered);

      if (rest.length === 0)
        return false; // Missing Signed

      const dnskey = keyMap.get(s.keyTag);

      if (!dnskey)
        return false; // Mising DNS Key

      if (!s.validityPeriod())
        return false; // Invalid Signature Period

      if (!dnssec.verify(sig, dnskey, rest))
        return false; // Invalid Signature

      set.delete(s.typeCovered);
    }

    if (set.size !== 0)
      return false; // Unsigned Data
  }

  return true;
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

dnssec.flags = flags;
dnssec.algs = algs;
dnssec.algsByVal = algsByVal;
dnssec.hashes = hashes;
dnssec.hashByVal = hashByVal;
dnssec.algToHash = algToHash;
dnssec.hashToHash = hashToHash;
