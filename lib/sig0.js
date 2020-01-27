/*!
 * sig0.js - SIG(0) for bns
 * Copyright (c) 2018, Christopher Jeffrey (MIT License).
 * https://github.com/chjj/bns
 *
 * Parts of this software are based on miekg/dns:
 *   https://github.com/miekg/dns/blob/master/sig0.go
 */

'use strict';

const assert = require('bsert');
const bio = require('bufio');
const constants = require('./constants');
const dnssec = require('./dnssec');
const encoding = require('./encoding');
const util = require('./util');
const wire = require('./wire');

const {
  types,
  classes,
  algs,
  algsByVal,
  hashes,
  hashesByVal,
  algHashes
} = constants;

const {
  algToHash,
  hashToHash
} = dnssec;

const {
  readNameBR,
  writeNameBW,
  sizeName,
  toName
} = encoding;

const {
  Record,
  KEYRecord,
  SIGRecord
} = wire;

/*
 * Constants
 */

const DUMMY = Buffer.alloc(0);
const DEFAULT_FUDGE = 300;

/*
 * SIG(0)
 */

const sig0 = exports;

sig0.filename = dnssec.filename;
sig0.privFile = dnssec.privFile;
sig0.pubFile = dnssec.pubFile;

sig0.createPrivate = dnssec.createPrivate;
sig0.createPrivateAsync = dnssec.createPrivateAsync;
sig0.createPublic = dnssec.createPublic;
sig0.encodePrivate = dnssec.encodePrivate;
sig0.decodePrivate = dnssec.decodePrivate;

sig0.readPrivate = dnssec.readPrivate;
sig0.readPrivateAsync = dnssec.readPrivateAsync;
sig0.readPublic = dnssec.readPublic;
sig0.readPublicAsync = dnssec.readPublicAsync;
sig0.writeKeys = dnssec.writeKeys;
sig0.writeKeysAsync = dnssec.writeKeysAsync;
sig0.writePrivate = dnssec.writePrivate;
sig0.writePrivateAsync = dnssec.writePrivateAsync;
sig0.writePublic = dnssec.writePublic;
sig0.writePublicAsync = dnssec.writePublicAsync;

sig0.makeKey = function makeKey(algorithm, priv) {
  const pub = sig0.createPublic(algorithm, priv);
  return sig0.createKey(algorithm, pub);
};

sig0.createKey = function createKey(algorithm, publicKey, prefix) {
  assert((algorithm & 0xff) === algorithm);
  assert(Buffer.isBuffer(publicKey));

  const rr = new Record();
  const rd = new KEYRecord();

  rr.name = '.';
  rr.class = classes.IN;
  rr.type = types.KEY;
  rr.ttl = 0;
  rr.data = rd;

  rd.flags = 0;
  rd.protocol = 0;
  rd.algorithm = algorithm;

  // https://tools.ietf.org/html/rfc4034#appendix-A.1.1
  // PRIVATEDNS publicKey should be wire encoded and prefixed with algo name
  if (algorithm === sig0.algs.PRIVATEDNS) {
    prefix = toName(prefix);
    const key = bio.write(sizeName(prefix) + publicKey.length);
    writeNameBW(key, prefix);
    key.writeBytes(publicKey);
    publicKey = key.render();
  }

  rd.publicKey = publicKey;

  return rr;
};

sig0.sign = function sign(msg, key, priv, fudge, signer) {
  if (fudge == null)
    fudge = DEFAULT_FUDGE;

  assert(Buffer.isBuffer(msg));
  assert(msg.length >= 12);
  assert(key instanceof Record);
  assert(key.type === types.KEY);
  assert(Buffer.isBuffer(priv));
  assert((fudge >>> 0) === fudge);
  assert(signer == null || typeof signer === 'function');

  const now = util.now();
  const rr = new Record();
  const rd = new SIGRecord();

  rr.name = '.';
  rr.type = types.SIG;
  rr.class = classes.ANY;
  rr.ttl = 0;
  rr.data = rd;
  rd.typeCovered = 0;
  rd.algorithm = key.data.algorithm;
  rd.labels = 0;
  rd.origTTL = 0;
  rd.expiration = now + fudge;
  rd.inception = now - fudge;
  rd.keyTag = key.data.keyTag();
  rd.signerName = '.';
  rd.signature = DUMMY;

  const pre = removeSIG(msg);
  const data = sigData(pre, rd, 0);

  if (rd.algorithm === algs.PRIVATEDNS) {
    if (!signer)
      throw new Error('Signer not available.');

    rd.signature = signer(priv, data);
  } else {
    rd.signature = dnssec.signData(priv, data, rd.algorithm);
  }

  const arcount = bio.readU16BE(pre, 10);
  const size = rr.getSize();
  const bw = bio.write(pre.length + size);

  bw.copy(pre, 0, 10);
  bw.writeU16BE(arcount + 1);
  bw.copy(pre, 12, pre.length);
  rr.write(bw);

  return bw.render();
};

sig0.verify = function verify(msg, key, verifier) {
  assert(Buffer.isBuffer(msg));
  assert(key instanceof Record);
  assert(key.type === types.KEY);
  assert(verifier == null || typeof verifier === 'function');

  const [pos, rr] = findSIG(msg);

  if (pos === -1)
    return false;

  const rd = rr.data;

  if (rd.algorithm !== key.data.algorithm)
    return false;

  if (rd.labels !== 0)
    return false;

  if (rd.origTTL !== 0)
    return false;

  const now = util.now();

  if (now < rd.inception)
    return false;

  if (now > rd.expiration)
    return false;

  if (rd.algorithm !== algs.PRIVATEDNS) {
    if (rd.keyTag !== key.data.keyTag())
      return false;
  }

  if (rd.signerName !== '.')
    return false;

  const pre = msg.slice(0, pos);
  const data = sigData(pre, rd, -1);

  if (rd.algorithm === algs.PRIVATEDNS) {
    if (!verifier)
      throw new Error('Verifier not available.');

    return verifier(rr, key, data);
  }

  return dnssec.verifyData(rr, key, data, rd.algorithm);
};

/*
 * Helpers
 */

function findSIG(msg) {
  assert(Buffer.isBuffer(msg));

  try {
    return _findSIG(msg);
  } catch (e) {
    return [-1, null];
  }
}

function _findSIG(msg) {
  const br = bio.read(msg);

  br.readU16BE();
  br.readU16BE();

  const qdcount = br.readU16BE();
  const ancount = br.readU16BE();
  const nscount = br.readU16BE();
  const arcount = br.readU16BE();

  if (arcount === 0)
    return [-1, null];

  for (let i = 0; i < qdcount; i++) {
    if (br.left() === 0)
      return [-1, null];

    readNameBR(br);
    br.seek(4);
  }

  for (let i = 0; i < ancount; i++) {
    if (br.left() === 0)
      return [-1, null];

    readNameBR(br);
    br.seek(8);
    br.seek(br.readU16BE());
  }

  for (let i = 0; i < nscount; i++) {
    if (br.left() === 0)
      return [-1, null];

    readNameBR(br);
    br.seek(8);
    br.seek(br.readU16BE());
  }

  for (let i = 0; i < arcount - 1; i++) {
    if (br.left() === 0)
      return [-1, null];

    readNameBR(br);
    br.seek(8);
    br.seek(br.readU16BE());
  }

  const offset = br.offset;
  const rr = Record.read(br);
  const rd = rr.data;

  if (rr.name !== '.')
    return [-1, null];

  if (rr.type !== types.SIG)
    return [-1, null];

  if (rr.class !== classes.ANY)
    return [-1, null];

  if (rr.ttl !== 0)
    return [-1, null];

  if (rd.typeCovered !== 0)
    return [-1, null];

  return [offset, rr];
}

function removeSIG(msg) {
  assert(Buffer.isBuffer(msg));
  assert(msg.length >= 12);

  const [pos] = findSIG(msg);

  if (pos === -1)
    return msg;

  const arcount = bio.readU16BE(msg, 10);
  const buf = Buffer.allocUnsafe(pos);
  msg.copy(buf, 0, 0, pos);
  bio.writeU16BE(buf, arcount - 1, 10);

  return buf;
}

function sigData(msg, rd, offset) {
  assert(Buffer.isBuffer(msg));
  assert(msg.length >= 12);
  assert(rd instanceof SIGRecord);
  assert(Number.isSafeInteger(offset));

  const sig = rd.signature;
  const arcount = bio.readU16BE(msg, 10);

  if (arcount + offset < 0)
    throw new Error('Invalid offset.');

  rd.signature = DUMMY;

  let size = 0;
  size += rd.getSize();
  size += msg.length;

  const bw = bio.write(size);

  rd.write(bw);
  bw.copy(msg, 0, 10);
  bw.writeU16BE(arcount + offset);
  bw.copy(msg, 12, msg.length);

  rd.signature = sig;

  return bw.render();
}

/*
 * Expose
 */

sig0.algs = algs;
sig0.algsByVal = algsByVal;
sig0.hashes = hashes;
sig0.hashesByVal = hashesByVal;
sig0.algHashes = algHashes;
sig0.algToHash = algToHash;
sig0.hashToHash = hashToHash;
