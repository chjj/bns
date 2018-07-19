/*!
 * crypto.js - crypto for bns
 * Copyright (c) 2018, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bns
 */

'use strict';

const assert = require('bsert');
const safeEqual = require('bcrypto/lib/safe-equal');
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

/*
 * Helpers
 */

exports.safeEqual = safeEqual;

/*
 * RSA
 */

exports.signRSA = function signRSA(hash, msg, key) {
  return rsa.sign(hash, msg, key);
};

exports.verifyRSA = function verifyRSA(hash, msg, sig, key) {
  const pub = toRSAKey(key);

  // Failed parsing.
  if (!pub)
    return false;

  // Basic sanity checks.
  if (!pub.verify())
    return false;

  // Limited to 4096:
  // https://tools.ietf.org/html/rfc3110#section-2
  // https://www.imperialviolet.org/2012/03/17/rsados.html
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

exports.rsaBits = function rsaBits(raw) {
  const pub = toRSAKey(raw);

  if (!pub)
    return 0;

  return pub.bits();
};

/*
 * Helpers
 */

function toRSAKey(raw) {
  assert(Buffer.isBuffer(raw));

  try {
    return RSAPublicKey.fromDNS(raw);
  } catch (e) {
    return null;
  }
}

function toECKey(raw) {
  assert(Buffer.isBuffer(raw));

  const key = Buffer.allocUnsafe(1 + raw.length);
  key[0] = 0x04;
  raw.copy(key, 1);

  return key;
}
