/*!
 * crypto.js - crypto for bns
 * Copyright (c) 2018, Christopher Jeffrey (MIT License).
 * https://github.com/chjj/bns
 */

'use strict';

const assert = require('bsert');
const bio = require('bufio');
const {safeEqual} = require('bcrypto/lib/safe');
const MD5 = require('bcrypto/lib/md5');
const SHA1 = require('bcrypto/lib/sha1');
const SHA224 = require('bcrypto/lib/sha224');
const SHA256 = require('bcrypto/lib/sha256');
const SHA384 = require('bcrypto/lib/sha384');
const SHA512 = require('bcrypto/lib/sha512');
const GOST94 = require('bcrypto/lib/gost94');
const dsa = require('bcrypto/lib/dsa');
const rsa = require('bcrypto/lib/rsa');
const p256 = require('bcrypto/lib/p256');
const p384 = require('bcrypto/lib/p384');
const ed25519 = require('bcrypto/lib/ed25519');
const ed448 = require('bcrypto/lib/ed448');
const {padLeft} = require('bcrypto/lib/encoding/util');

/*
 * Hashes
 */

exports.md5 = MD5;
exports.sha1 = SHA1;
exports.sha224 = SHA224;
exports.sha256 = SHA256;
exports.sha384 = SHA384;
exports.sha512 = SHA512;
exports.gost94 = GOST94;

/*
 * Helpers
 */

exports.safeEqual = safeEqual;

/*
 * DSA
 */

exports.generateDSA = function generateDSA(bits) {
  if (bits == null)
    bits = 1024;

  assert((bits >>> 0) === bits);

  if (bits > 1024)
    throw new RangeError('DSA prime cannot exceed 1024 bits.');

  return dsa.privateKeyGenerate(bits);
};

exports.generateDSAAsync = async function generateDSAAsync(bits) {
  if (bits == null)
    bits = 1024;

  assert((bits >>> 0) === bits);

  if (bits > 1024)
    throw new RangeError('DSA prime cannot exceed 1024 bits.');

  return dsa.privateKeyGenerateAsync(bits);
};

exports.createDSA = function createDSA(key) {
  const pub = dsa.publicKeyCreate(key);
  return dsaKeyExport(pub);
};

exports.signDSA = function signDSA(hash, data, key) {
  assert(hash && typeof hash.id === 'string');

  const {p, q} = dsa.privateKeyExport(key);

  if (p.length > 1024 / 8 || q.length !== 20)
    throw new Error('Invalid DSA private key.');

  const msg = hash.digest(data);
  const sig = dsa.sign(msg, key);

  return dsaSigExport(sig, key);
};

exports.verifyDSA = function verifyDSA(hash, data, sig, key) {
  assert(hash && typeof hash.id === 'string');
  assert(Buffer.isBuffer(key));
  assert(Buffer.isBuffer(sig));

  let pub;
  try {
    pub = dsaKeyImport(key);
  } catch (e) {
    return false;
  }

  let s;
  try {
    s = dsaSigImport(sig);
  } catch (e) {
    return false;
  }

  const {p, q} = dsa.publicKeyExport(pub);

  if (p.length > 1024 / 8 || q.length !== 20)
    return false;

  const msg = hash.digest(data);

  return dsa.verify(msg, s, pub);
};

/*
 * RSA
 */

exports.generateRSA = function generateRSA(bits, exp) {
  if (bits == null)
    bits = 2048;

  assert((bits >>> 0) === bits);
  assert(bits <= 4096);

  return rsa.privateKeyGenerate(bits, exp);
};

exports.generateRSAAsync = async function generateRSAAsync(bits, exp) {
  if (bits == null)
    bits = 2048;

  assert((bits >>> 0) === bits);
  assert(bits <= 4096);

  return rsa.privateKeyGenerateAsync(bits, exp);
};

exports.createRSA = function createRSA(key) {
  const pub = rsa.publicKeyCreate(key);
  return rsaKeyExport(pub);
};

exports.signRSA = function signRSA(hash, data, key) {
  assert(hash && typeof hash.id === 'string');

  const msg = hash.digest(data);

  return rsa.sign(hash, msg, key);
};

exports.verifyRSA = function verifyRSA(hash, data, sig, key) {
  assert(hash && typeof hash.id === 'string');
  assert(Buffer.isBuffer(sig));

  let pub;
  try {
    pub = rsaKeyImport(key);
  } catch (e) {
    return false;
  }

  // Modulus limited to 4096 bits.
  //
  // See:
  //   - https://tools.ietf.org/html/rfc3110#section-2
  //   - https://www.imperialviolet.org/2012/03/17/rsados.html
  //   - https://github.com/isc-projects/bind9/blob/fa03f94/lib/dns/opensslrsa_link.c#L482
  //
  // Note that our RSA implementation limits
  // the exponent to 33 bits. This differs
  // from BIND which limits it at 35. 33 was
  // chosen because a lot of people use
  // `0x01000001` as an exponent for DNSSEC
  // (due BIND's dnssec-keygen using a stupid
  // exponent for no reason).
  //
  // See:
  //   - https://www.imperialviolet.org/2012/03/16/rsae.html
  //   - https://github.com/isc-projects/bind9/blob/fa03f94/lib/dns/opensslrsa_link.c#L47
  const bits = rsa.publicKeyBits(pub);

  if (bits > 4096)
    return false;

  const msg = hash.digest(data);

  // Since BIND is essentially "DNSSEC consensus"
  // we do something here once again. None of
  // this is specified in any RFC, but in order
  // to maintain compatibility with BIND, RSA
  // signatures which are smaller than the key's
  // modulus (in terms of bytes) must be accepted.
  // This is due to BIND's usage of OpenSSL's
  // EVP interface.
  //
  // This means a signature which is created with
  // leading zero bytes are allowed to have them
  // chopped off before hitting the protocol layer.
  // According to OpenSSL, PGP implementations
  // also do funky stuff like this!
  //
  // See:
  //   - https://github.com/isc-projects/bind9/blob/fa03f94/lib/dns/opensslrsa_link.c#L352
  //   - https://github.com/openssl/openssl/blob/41bfd5e/crypto/rsa/rsa_ossl.c#L538
  //
  // Note that the raw OpenSSL RSA api requires
  // signatures be a proper length:
  //   - https://github.com/openssl/openssl/blob/41bfd5e/crypto/rsa/rsa_saos.c#L64
  const size = (bits + 7) >>> 3;

  if (sig.length < size)
    sig = padLeft(sig, size);

  return rsa.verify(hash, msg, sig, pub);
};

/*
 * P256
 */

exports.generateP256 = function generateP256() {
  return p256.privateKeyGenerate();
};

exports.createP256 = function createP256(key) {
  const {x, y} = p256.privateKeyExport(key);
  return Buffer.concat([x, y]);
};

exports.signP256 = function signP256(hash, data, key) {
  assert(hash && typeof hash.id === 'string');

  const msg = hash.digest(data);

  return p256.sign(msg, key);
};

exports.verifyP256 = function verifyP256(hash, data, sig, key) {
  assert(hash && typeof hash.id === 'string');
  assert(Buffer.isBuffer(key));

  if (key.length !== 64)
    return false;

  let pub;
  try {
    pub = p256.publicKeyImport({
      x: key.slice(0, 32),
      y: key.slice(32)
    });
  } catch (e) {
    return false;
  }

  const msg = hash.digest(data);

  return p256.verify(msg, sig, pub);
};

/*
 * P384
 */

exports.generateP384 = function generateP384() {
  return p384.privateKeyGenerate();
};

exports.createP384 = function createP384(key) {
  const {x, y} = p384.privateKeyExport(key);
  return Buffer.concat([x, y]);
};

exports.signP384 = function signP384(hash, data, key) {
  assert(hash && typeof hash.id === 'string');

  const msg = hash.digest(data);

  return p384.sign(msg, key);
};

exports.verifyP384 = function verifyP384(hash, data, sig, key) {
  assert(hash && typeof hash.id === 'string');
  assert(Buffer.isBuffer(key));

  if (key.length !== 96)
    return false;

  let pub;
  try {
    pub = p384.publicKeyImport({
      x: key.slice(0, 48),
      y: key.slice(48)
    });
  } catch (e) {
    return false;
  }

  const msg = hash.digest(data);

  return p384.verify(msg, sig, pub);
};

/*
 * ED25519
 */

exports.generateED25519 = function generateED25519() {
  return ed25519.privateKeyGenerate();
};

exports.createED25519 = function createED25519(key) {
  return ed25519.publicKeyCreate(key);
};

exports.signED25519 = function signED25519(data, key) {
  return ed25519.sign(data, key);
};

exports.verifyED25519 = function verifyED25519(data, sig, key) {
  return ed25519.verify(data, sig, key);
};

/*
 * ED448
 */

exports.generateED448 = function generateED448() {
  return ed448.privateKeyGenerate();
};

exports.createED448 = function createED448(key) {
  return ed448.publicKeyCreate(key);
};

exports.signED448 = function signED448(data, key) {
  return ed448.sign(data, key);
};

exports.verifyED448 = function verifyED448(data, sig, key) {
  return ed448.verify(data, sig, key);
};

/*
 * Helpers
 */

exports.rsaBits = function rsaBits(raw) {
  assert(Buffer.isBuffer(raw));

  let pub;
  try {
    pub = rsaKeyImport(raw);
  } catch (e) {
    return 0;
  }

  return rsa.publicKeyBits(pub);
};

/*
 * Helpers
 */

function rsaKeyExport(key) {
  const {n, e} = rsa.publicKeyExport(key);

  let size = 1 + e.length + n.length;

  if (e.length > 255)
    size += 2;

  const bw = bio.write(size);

  if (e.length > 255) {
    bw.writeU8(0);
    bw.writeU16BE(e.length);
  } else {
    bw.writeU8(e.length);
  }

  bw.writeBytes(e);
  bw.writeBytes(n);

  return bw.render();
}

function rsaKeyImport(data) {
  assert(Buffer.isBuffer(data));

  const br = bio.read(data);

  let len = br.readU8();

  if (len === 0)
    len = br.readU16BE();

  const e = br.readBytes(len);
  const n = br.readBytes(br.left());

  return rsa.publicKeyImport({ n, e });
}

function dsaKeyExport(key) {
  const {p, q, g, y} = dsa.publicKeyExport(key);

  if (p.length < 64 || q.length > 20)
    throw new Error('Invalid DSA public key.');

  const T = ((p.length - 64) + 7) >>> 3;
  const len = 64 + T * 8;

  if (p.length > len)
    throw new Error('Invalid P value.');

  const size = 21 + len * 3;
  const bw = bio.write(size);

  bw.writeU8(T);
  bw.writeBytes(padLeft(q, 20));
  bw.writeBytes(padLeft(p, len));
  bw.writeBytes(padLeft(g, len));
  bw.writeBytes(padLeft(y, len));

  return bw.render();
}

function dsaKeyImport(data) {
  assert(Buffer.isBuffer(data));

  // See: https://github.com/NLnetLabs/ldns/blob/develop/dnssec.c#L337
  const br = bio.read(data);

  // Compressed L value.
  const T = br.readU8();

  if (T > 8)
    throw new Error('Invalid L value.');

  // L = 512 + T (max=1024)
  // N = 160
  const len = 64 + T * 8;
  const q = br.readBytes(20);
  const p = br.readBytes(len);
  const g = br.readBytes(len);
  const y = br.readBytes(len);

  return dsa.publicKeyImport({ p, q, g, y });
}

function dsaSigExport(sig, key) {
  assert(Buffer.isBuffer(sig));

  const {p, q} = dsa.privateKeyExport(key);

  if (p.length < 64 || q.length > 20)
    throw new Error('Invalid DSA private key.');

  const T = ((p.length - 64) + 7) >>> 3;
  const len = 64 + T * 8;

  if (p.length > len)
    throw new Error('Invalid P value.');

  if (sig.length !== q.length * 2)
    throw new Error('Invalid signature.');

  const r = sig.slice(0, q.length);
  const s = sig.slice(q.length);
  const bw = bio.write(41);

  bw.writeU8(T);
  bw.writeBytes(padLeft(r, 20));
  bw.writeBytes(padLeft(s, 20));

  return bw.render();
}

function dsaSigImport(data) {
  assert(Buffer.isBuffer(data));

  // Signatures are [T] [R] [S] (20 byte R and S) -- T is ignored.
  // See: https://github.com/NLnetLabs/ldns/blob/develop/dnssec.c#L1795
  // See: https://github.com/miekg/dns/blob/master/dnssec.go#L373
  const br = bio.read(data);

  // Compressed L value.
  const T = br.readU8();

  if (T > 8)
    throw new Error('Invalid L value.');

  return br.readBytes(40);
}
