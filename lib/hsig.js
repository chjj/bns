/*!
 * hsig.js - HSIG for bns
 * Copyright (c) 2018, Christopher Jeffrey (MIT License).
 * https://github.com/chjj/bns
 */

'use strict';

const assert = require('bsert');
const secp256k1 = require('bcrypto/lib/secp256k1');
const blake2b = require('bcrypto/lib/blake2b');
const sig0 = require('./sig0');

/*
 * Constants
 */

const FUDGE_WINDOW = 21600; // 6 hours

/*
 * HSIG
 */

const hsig = exports;

hsig.createPrivate = function createPrivate() {
  return secp256k1.privateKeyGenerate();
};

hsig.createPrivateAsync = hsig.createPrivate;

hsig.createPublic = function createPublic(priv) {
  return secp256k1.publicKeyCreate(priv);
};

hsig.makeKey = function makeKey(priv) {
  const pub = secp256k1.publicKeyCreate(priv);
  return hsig.createKey(pub);
};

hsig.createKey = function createKey(pub) {
  return sig0.createKey(sig0.algs.PRIVATEDNS, pub);
};

hsig.sign = function sign(msg, priv) {
  assert(Buffer.isBuffer(msg));
  assert(Buffer.isBuffer(priv) && priv.length === 32);

  const pub = secp256k1.publicKeyCreate(priv, true);
  const key = hsig.createKey(pub);
  const fudge = FUDGE_WINDOW;

  return sig0.sign(msg, key, priv, fudge, (priv, data) => {
    const msg = blake2b.digest(data);
    return secp256k1.sign(msg, priv);
  });
};

hsig.verify = function verify(msg, pub) {
  assert(Buffer.isBuffer(msg));
  assert(Buffer.isBuffer(pub) && pub.length === 33);

  const key = hsig.createKey(pub);

  return sig0.verify(msg, key, (sig, key, data) => {
    const msg = blake2b.digest(data);
    const sigbuf = sig.data.signature;
    const keybuf = key.data.publicKey;
    return secp256k1.verify(msg, sigbuf, keybuf);
  });
};
