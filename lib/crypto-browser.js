/*!
 * crypto.js - crypto for bns
 * Copyright (c) 2018, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bns
 */

'use strict';

/*
 * Hashes
 */

exports.md5 = undefined;
exports.sha1 = undefined;
exports.sha256 = undefined;
exports.sha384 = undefined;
exports.sha512 = undefined;
exports.ccmp = undefined;

/*
 * RSA
 */

exports.signRSA = function signRSA(hash, data, key) {
  throw new Error('Cannot sign.');
};

exports.verifyRSA = function verifyRSA(hash, data, sig, key) {
  throw new Error('Cannot verify.');
};

/*
 * ECDSA
 */

exports.signECDSA = function signECDSA(curve, hash, data, key) {
  throw new Error('Cannot sign.');
};

exports.verifyECDSA = function verifyECDSA(curve, hash, data, sig, key) {
  throw new Error('Cannot verify.');
};

/*
 * EDDSA
 */

exports.signEDDSA = function signEDDSA(curve, hash, data, key) {
  throw new Error('Cannot sign.');
};

exports.verifyEDDSA = function verifyEDDSA(curve, hash, data, sig, key) {
  throw new Error('Cannot verify.');
};
