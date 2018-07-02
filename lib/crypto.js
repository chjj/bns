/*!
 * crypto.js - crypto for bns
 * Copyright (c) 2018, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bns
 */

'use strict';

const assert = require('assert');
const ccmp = require('bcrypto/lib/ccmp');
const MD5 = require('bcrypto/lib/md5');
const SHA1 = require('bcrypto/lib/sha1');
const SHA224 = require('bcrypto/lib/sha224');
const SHA256 = require('bcrypto/lib/sha256');
const SHA384 = require('bcrypto/lib/sha384');
const SHA512 = require('bcrypto/lib/sha512');
const rsa = require('bcrypto/lib/rsa');
const p256 = require('bcrypto/lib/p256');
const p384 = require('bcrypto/lib/p384');
const ed25519 = require('bcrypto/lib/ed25519');
const {RSAPublicKey} = rsa;

/*
 * Hashes
 */

exports.md5 = MD5;
exports.sha1 = SHA1;
exports.sha224 = SHA224;
exports.sha256 = SHA256;
exports.sha384 = SHA384;
exports.sha512 = SHA512;
exports.ccmp = ccmp;

/*
 * RSA
 */

exports.signRSA = function signRSA(hash, msg, key) {
  return rsa.sign(hash, msg, key);
};

exports.verifyRSA = function verifyRSA(hash, msg, sig, key) {
  const pub = toRSAKey(key);

  if (!pub)
    return false;

  if (!rsa.publicVerify(pub))
    return false;

  if (pub.bits() > 4096)
    return false;

  return rsa.verifyKey(hash, msg, sig, pub);
};

/*
 * P256
 */

exports.signP256 = function signP256(hash, data, key) {
  assert(hash && typeof hash.id === 'string', 'No algorithm selected.');
  const msg = hash.digest(data);
  return p256.sign(msg, key);
};

exports.verifyP256 = function verifyP256(hash, data, sig, key) {
  assert(hash && typeof hash.id === 'string', 'No algorithm selected.');
  const msg = hash.digest(data);
  const pub = toECKey(key);
  return p256.verify(msg, sig, pub);
};

/*
 * P384
 */

exports.signP384 = function signP384(hash, data, key) {
  assert(hash && typeof hash.id === 'string', 'No algorithm selected.');
  const msg = hash.digest(data);
  return p384.sign(msg, key);
};

exports.verifyP384 = function verifyP384(hash, data, sig, key) {
  assert(hash && typeof hash.id === 'string', 'No algorithm selected.');
  const msg = hash.digest(data);
  const pub = toECKey(key);
  return p384.verify(msg, sig, pub);
};

/*
 * ED25519
 */

exports.signED25519 = function signED25519(hash, data, key) {
  assert(hash && typeof hash.id === 'string', 'No algorithm selected.');
  const msg = hash.digest(data);
  return ed25519.sign(msg, key);
};

exports.verifyED25519 = function verifyED25519(hash, data, sig, key) {
  assert(hash && typeof hash.id === 'string', 'No algorithm selected.');
  const msg = hash.digest(data);
  return ed25519.verify(msg, sig, key);
};

/*
 * Helpers
 */

exports.rsaBits = function rsaBits(key) {
  const pub = toRSAKey(key);

  if (!pub)
    return 0;

  return pub.bits();
};

/*
 * Helpers
 */

function toRSAKey(buf) {
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

  const pub = new RSAPublicKey();

  pub.n = trimZeroes(n);
  pub.e = trimZeroes(e);

  return pub;
}

function toECKey(buf) {
  assert(Buffer.isBuffer(buf));

  const key = Buffer.allocUnsafe(1 + buf.length);
  key[0] = 0x04;
  buf.copy(key, 1);

  return key;
}

function trimZeroes(buf) {
  assert(Buffer.isBuffer(buf));

  if (buf.length === 0)
    return Buffer.from([0x00]);

  if (buf[0] !== 0)
    return buf;

  for (let i = 1; i < buf.length; i++) {
    if (buf[i] !== 0)
      return buf.slice(i);
  }

  return buf.slice(-1);
}
