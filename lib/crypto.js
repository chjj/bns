/*!
 * crypto.js - crypto for bns
 * Copyright (c) 2018, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bns
 */

'use strict';

const assert = require('assert');
const crypto = require('crypto');
const bio = require('bufio');
const elliptic = require('elliptic');
const Signature = require('elliptic/lib/elliptic/ec/signature');
const EdDSA = elliptic.eddsa;

/*
 * Hashing
 */

class BaseHash {
  constructor(name) {
    this.name = name;
    this.ctx = null;
  }

  init() {
    assert(!this.ctx);
    this.ctx = crypto.createHash(this.name);
    return this;
  }

  update(data) {
    assert(this.ctx);
    this.ctx.update(data);
    return this;
  }

  final() {
    assert(this.ctx);
    const hash = this.ctx.digest();
    this.ctx = null;
    return hash;
  }
}

function createHash(name) {
  return class Hash extends BaseHash {
    constructor() {
      super(name);
    }

    static hash() {
      return new this();
    }

    static digest(data) {
      const ctx = new this();
      return ctx.init().update(data).final();
    }

    static get name() {
      return name;
    }
  };
}

/*
 * Hashes
 */

exports.md5 = createHash('md5');
exports.sha1 = createHash('sha1');
exports.sha256 = createHash('sha256');
exports.sha384 = createHash('sha384');
exports.sha512 = createHash('sha512');

/*
 * RSA
 */

exports.signRSA = function signRSA(hash, data, key) {
  assert(hash && typeof hash.name === 'string', 'No algorithm selected.');
  assert(Buffer.isBuffer(data));
  assert(Buffer.isBuffer(key));

  const name = toName('RSA', hash);
  const pem = toPEM(key, 'RSA PRIVATE KEY');
  const ctx = crypto.createSign(name);

  ctx.update(data);

  return ctx.sign(pem);
};

exports.verifyRSA = function verifyRSA(hash, data, sig, key) {
  assert(hash && typeof hash.name === 'string', 'No algorithm selected.');
  assert(Buffer.isBuffer(data));
  assert(Buffer.isBuffer(sig));
  assert(Buffer.isBuffer(key));

  const name = toName('RSA', hash);
  const asn1 = toASN1(key);

  if (!asn1)
    return false;

  const pem = toPEM(asn1, 'RSA PUBLIC KEY');
  const ctx = crypto.createVerify(name);

  try {
    ctx.update(data);
    return ctx.verify(pem, sig);
  } catch (e) {
    return false;
  }
};

/*
 * ECDSA
 */

exports.signECDSA = function signECDSA(curve, hash, data, key) {
  assert(typeof curve === 'string', 'No curve selected.');
  assert(hash && typeof hash.name === 'string', 'No algorithm selected.');
  assert(Buffer.isBuffer(data));
  assert(Buffer.isBuffer(key));

  const size = curveSize(curve);
  assert(size !== 0, 'Unknown curve.');

  const ec = elliptic.ec(curve);
  const msg = hash.digest(data);
  const sig = ec.sign(msg, key, { canonical: true });

  const r = sig.r.toArrayLike(Buffer, 'be', size);
  const s = sig.s.toArrayLike(Buffer, 'be', size);

  return Buffer.concat([r, s]);
};

exports.verifyECDSA = function verifyECDSA(curve, hash, data, sig, key) {
  assert(typeof curve === 'string', 'No curve selected.');
  assert(hash && typeof hash.name === 'string', 'No algorithm selected.');
  assert(Buffer.isBuffer(data));
  assert(Buffer.isBuffer(sig));
  assert(Buffer.isBuffer(key));

  const size = curveSize(curve);
  assert(size !== 0, 'Unknown curve.');

  if (sig.length !== size * 2)
    return false;

  if (key.length !== size * 2)
    return false;

  const r = sig.slice(0, size);
  const s = sig.slice(size, size + size);
  const dsig = new Signature({ r, s }).toDER();

  const fkey = Buffer.allocUnsafe(1 + key.length);
  fkey[0] = 0x04;
  key.copy(fkey, 1);

  const ec = elliptic.ec(curve);
  const msg = hash.digest(data);

  try {
    return ec.verify(msg, dsig, fkey);
  } catch (e) {
    return false;
  }
};

/*
 * EDDSA
 */

exports.signEDDSA = function signEDDSA(curve, hash, data, key) {
  assert(typeof curve === 'string', 'No curve selected.');
  assert(hash && typeof hash.name === 'string', 'No algorithm selected.');
  assert(Buffer.isBuffer(data));
  assert(Buffer.isBuffer(key));
  assert(elliptic.curves[curve], 'Unknown curve.');

  const ed = new EdDSA(curve);
  const msg = hash.digest(data);
  const sig = ed.sign(msg, key, { canonical: true });

  return sig.toBytes();
};

exports.verifyEDDSA = function verifyEDDSA(curve, hash, data, sig, key) {
  assert(typeof curve === 'string', 'No curve selected.');
  assert(hash && typeof hash.name === 'string', 'No algorithm selected.');
  assert(Buffer.isBuffer(data));
  assert(Buffer.isBuffer(sig));
  assert(Buffer.isBuffer(key));
  assert(elliptic.curves[curve], 'Unknown curve.');

  const ed = new EdDSA(curve);
  const size = ed.encodingLength;

  if (sig.length !== size * 2)
    return false;

  if (key.length !== size * 2)
    return false;

  const msg = hash.digest(data);

  try {
    return ed.verify(msg, sig, key);
  } catch (e) {
    return false;
  }
};

/*
 * Helpers
 */

function toName(alg, hash) {
  return `${alg}-${hash.name.toUpperCase()}`;
}

function toPEM(der, type) {
  let pem = '';

  der = der.toString('base64');

  for (let i = 0; i < der.length; i += 64)
    pem += der.slice(i, i + 64) + '\n';

  return ''
    + `-----BEGIN ${type}-----\n`
    + pem
    + `-----END ${type}-----\n`;
}

function curveSize(curve) {
  const desc = elliptic.curves[curve];

  if (!desc)
    return 0;

  return desc.hash.outSize >>> 3;
}

function toASN1(buf) {
  assert(Buffer.isBuffer(buf));

  if (buf.length === 0)
    return null;

  let explen = buf[0];
  let keyoff = 1;

  if (explen === 0) {
    if (buf.length < 3)
      return null;
    explen = (buf[1] << 8) | buf[2];
    keyoff = 3;
  }

  if (buf.length < keyoff + explen)
    return null;

  const e = buf.slice(keyoff, keyoff + explen);
  const n = buf.slice(keyoff + explen);
  const s = 4 + n.length + 4 + e.length;
  const bw = bio.write(4 + s);

  bw.writeU8(0x10 | 0x20); // seq
  bw.writeU8(0x80 | 2); // long form
  bw.writeU16BE(s);

  bw.writeU8(0x02); // int
  bw.writeU8(0x80 | 2); // long form
  bw.writeU16BE(n.length);
  bw.writeBytes(n);

  // XXX Maybe allow to be bigger.
  // bw.writeU8(0x02); // int
  // bw.writeU8(e.length); // short form
  bw.writeU8(0x02); // int
  bw.writeU8(0x80 | 2); // long form
  bw.writeU16BE(e.length);
  bw.writeBytes(e);

  return bw.render();
}
