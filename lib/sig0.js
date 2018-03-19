/*!
 * sig0.js - SIG(0) for bns
 * Copyright (c) 2018, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bns
 *
 * Parts of this software are based on miekg/dns:
 *   https://github.com/miekg/dns/blob/master/sig0.go
 */

'use strict';

const assert = require('assert');
const bio = require('bufio');
const dnssec = require('./dnssec');
const encoding = require('./encoding');
const util = require('./util');
const wire = require('./wire');
const {readNameBR} = encoding;

const {
  types,
  classes,
  flags,
  Record,
  SIGRecord
} = wire;

const sig0 = exports;

const DUMMY = Buffer.alloc(0);

sig0.algs = dnssec.algs;
sig0.algsByVal = dnssec.algsByVal;
sig0.hashes = dnssec.hashes;
sig0.hashesByVal = dnssec.hashesByVal;
sig0.algToHash = dnssec.algToHash;
sig0.hashToHash = dnssec.hashToHash;

sig0.FUDGE_WINDOW = 6 * 60;

sig0.findSignature = function findSignature(msg) {
  assert(Buffer.isBuffer(msg));

  try {
    return sig0._findSignature(msg);
  } catch (e) {
    return [-1, null];
  }
};

sig0._findSignature = function _findSignature(msg) {
  const br = bio.read(msg);

  br.readU16BE();

  const bits = br.readU16BE();
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
    if (bits & flags.TC) {
      if (br.left() === 0)
        return [-1, null];
    }

    readNameBR(br);
    br.seek(8);
    br.seek(br.readU16BE());
  }

  for (let i = 0; i < nscount; i++) {
    if (bits & flags.TC) {
      if (br.left() === 0)
        return [-1, null];
    }

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
};

sig0.sign = function sign(msg, key, priv, signer) {
  assert(Buffer.isBuffer(msg));
  assert(msg.length >= 12);
  assert(key instanceof Record);
  assert(key.type === types.KEY);
  assert(Buffer.isBuffer(priv));
  assert(signer == null || typeof signer === 'function');

  let arcount = msg.readUInt16BE(10, true);

  const [pos] = sig0.findSignature(msg);

  if (pos !== -1) {
    const buf = Buffer.allocUnsafe(pos);
    msg.copy(buf, 0, 0, pos);
    arcount -= 1;
    buf.writeUInt16BE(arcount, 10, true);
    msg = buf;
  }

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
  rd.expiration = now + sig0.FUDGE_WINDOW;
  rd.inception = now - sig0.FUDGE_WINDOW;
  rd.keyTag = key.data.keyTag();
  rd.signerName = '.';
  rd.signature = DUMMY;

  const size1 = rd.getSize() + msg.length;
  const bw1 = bio.write(size1);
  rd.write(bw1);
  bw1.writeBytes(msg);

  const data = bw1.render();

  if (rd.algorithm === sig0.algs.PRIVATEDNS) {
    if (!signer)
      throw new Error('Signer not available.');

    rd.signature = signer(priv, data);
  } else {
    rd.signature = sig0.signData(priv, data, rd.algorithm);
  }

  const size2 = msg.length + rr.getSize();
  const bw2 = bio.write(size2);
  bw2.writeBytes(msg);
  rr.write(bw2);

  const out = bw2.render();
  out.writeUInt16BE(arcount + 1, 10, true);

  return out;
};

sig0.signData = function signData(priv, data, algorithm) {
  return dnssec.signData(priv, data, algorithm);
};

sig0.verify = function verify(msg, key, verifier) {
  assert(Buffer.isBuffer(msg));
  assert(key instanceof Record);
  assert(key.type === types.KEY);
  assert(verifier == null || typeof verifier === 'function');

  const [offset, rr] = sig0.findSignature(msg);

  if (offset === -1)
    return false;

  const rd = rr.data;

  if (rd.algorithm !== key.data.algorithm)
    return false;

  if (rd.labels !== 0)
    return false;

  if (rd.origTTL !== 0)
    return false;

  const now = util.now();

  if (now > rd.expiration)
    return false;

  if (now < rd.inception)
    return false;

  // A little lax for now.
  // if (rd.keyTag !== key.data.keyTag())
  //   return false;

  if (rd.signerName !== '.')
    return false;

  const arcount = msg.readUInt16BE(10, true);
  const pre = msg.slice(0, offset);
  const sig = rd.signature;

  rd.signature = DUMMY;

  const rdlen = rd.getSize();
  const size = rdlen + pre.length;

  const bw = bio.write(size);
  rd.write(bw);
  bw.writeBytes(pre);

  rd.signature = sig;

  const data = bw.render();
  data.writeUInt16BE(arcount - 1, rdlen + 10, true);

  if (rd.algorithm === sig0.algs.PRIVATEDNS) {
    if (!verifier)
      throw new Error('Verifier not available.');

    return verifier(rr, key, data);
  }

  return sig0.verifyData(rr, key, data, rd.algorithm);
};

sig0.verifyData = function verifyData(sig, key, data, algorithm) {
  return dnssec.verifyData(sig, key, data, algorithm);
};
