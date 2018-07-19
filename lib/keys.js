/*!
 * keys.js - DNSSEC keys for bns
 * Copyright (c) 2018, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bns
 */

'use strict';

const assert = require('bsert');
const rsa = require('bcrypto/lib/rsa');
const p256 = require('bcrypto/lib/p256');
const p384 = require('bcrypto/lib/p384');
const ed25519 = require('bcrypto/lib/ed25519');
const constants = require('./constants');
const util = require('./util');

const {
  algs,
  algToString
} = constants;

const {
  RSAPrivateKey
} = rsa;

const {
  pad
} = util;

/*
 * Constants
 */

const VERSION = 'v1.3';

/*
 * Keys
 */

const keys = exports;

keys.filename = function filename(name, alg, tag) {
  assert(typeof name === 'string');
  assert(util.isName(name));
  assert((alg & 0xff) === alg);
  assert((tag & 0xffff) === tag);

  const fqdn = util.fqdn(name.toLowerCase());

  return `K${fqdn}+${pad(alg, 3)}+${pad(tag, 5)}`;
};

keys.privFile = function privFile(name, alg, tag) {
  const file = keys.filename(name, alg, tag);
  return `${file}.private`;
};

keys.pubFile = function pubFile(name, alg, tag) {
  const file = keys.filename(name, alg, tag);
  return `${file}.key`;
};

keys.createPrivate = function createPrivate(algorithm, bits) {
  assert((algorithm & 0xff) === algorithm);

  switch (algorithm) {
    case algs.RSAMD5:
    case algs.RSASHA1:
    case algs.RSASHA1NSEC3SHA1:
    case algs.RSASHA256:
    case algs.RSASHA512:
      return rsa.privateKeyGenerate(bits);
    case algs.ECDSAP256SHA256:
      return p256.privateKeyGenerate();
    case algs.ECDSAP384SHA384:
      return p384.privateKeyGenerate();
    case algs.ED25519:
      return ed25519.privateKeyGenerate();
    default:
      throw new Error(`Unsupported algorithm: ${algToString(algorithm)}.`);
  }
};

keys.createPublic = function createPublic(algorithm, raw) {
  assert((algorithm & 0xff) === algorithm);
  assert(Buffer.isBuffer(raw));

  switch (algorithm) {
    case algs.RSAMD5:
    case algs.RSASHA1:
    case algs.RSASHA1NSEC3SHA1:
    case algs.RSASHA256:
    case algs.RSASHA512: {
      const priv = RSAPrivateKey.decode(raw);
      const pub = priv.toPublic();
      return pub.toDNS();
    }
    case algs.ECDSAP256SHA256: {
      return p256.publicKeyCreate(raw, false).slice(1);
    }
    case algs.ECDSAP384SHA384: {
      return p384.publicKeyCreate(raw, false).slice(1);
    }
    case algs.ED25519: {
      return ed25519.publicKeyCreate(raw);
    }
    default:
      throw new Error(`Unsupported algorithm: ${algToString(algorithm)}.`);
  }
};

keys.encodePrivate = function encodePrivate(algorithm, raw, time) {
  if (time == null)
    time = util.now();

  assert((algorithm & 0xff) === algorithm);
  assert(Buffer.isBuffer(raw));
  assert(Number.isSafeInteger(time) && time >= 0);

  switch (algorithm) {
    case algs.RSAMD5:
    case algs.RSASHA1:
    case algs.RSASHA1NSEC3SHA1:
    case algs.RSASHA256:
    case algs.RSASHA512:
      return keys.encodeRSA(algorithm, raw, time);
    case algs.ECDSAP256SHA256:
    case algs.ECDSAP384SHA384:
    case algs.ED25519:
      return keys.encodeEC(algorithm, raw, time);
    default:
      throw new Error(`Unsupported algorithm: ${algToString(algorithm)}.`);
  }
};

keys.encodeRSA = function encodeRSA(algorithm, raw, time) {
  assert((algorithm & 0xff) === algorithm);
  assert(Buffer.isBuffer(raw));

  const key = RSAPrivateKey.decode(raw);
  const now = util.serializeTime(time);

  return [
    `Private-key-format: ${VERSION}`,
    `Algorithm: ${algorithm} (${algToString(algorithm)})`,
    `Modulus: ${key.n.toString('base64')}`,
    `PublicExponent: ${key.e.toString('base64')}`,
    `PrivateExponent: ${key.d.toString('base64')}`,
    `Prime1: ${key.p.toString('base64')}`,
    `Prime2: ${key.q.toString('base64')}`,
    `Exponent1: ${key.dp.toString('base64')}`,
    `Exponent2: ${key.dq.toString('base64')}`,
    `Coefficient: ${key.qi.toString('base64')}`,
    `Created: ${now}`,
    `Publish: ${now}`,
    `Activate: ${now}`
  ].join('\n');
};

keys.encodeEC = function encodeEC(algorithm, raw, time) {
  assert((algorithm & 0xff) === algorithm);
  assert(Buffer.isBuffer(raw));

  const now = util.serializeTime(time);

  return [
    `Private-key-format: ${VERSION}`,
    `Algorithm: ${algorithm} (${algToString(algorithm)})`,
    `PrivateKey: ${raw.toString('base64')}`,
    `Created: ${now}`,
    `Publish: ${now}`,
    `Activate: ${now}`
  ].join('\n');
};

keys.decodePrivate = function decodePrivate(str) {
  const {algorithm} = keys.decodeMeta(str);

  switch (algorithm) {
    case algs.RSAMD5:
    case algs.RSASHA1:
    case algs.RSASHA1NSEC3SHA1:
    case algs.RSASHA256:
    case algs.RSASHA512:
      return keys.decodeRSA(str);
    case algs.ECDSAP256SHA256:
    case algs.ECDSAP384SHA384:
    case algs.ED25519:
      return keys.decodeEC(str);
    default:
      throw new Error(`Unsupported algorithm: ${algToString(algorithm)}.`);
  }
};

keys.decodeMeta = function decodeMeta(str) {
  assert(typeof str === 'string');

  const lines = util.splitLines(str);

  let format = VERSION;
  let algorithm = -1;
  let created = 0;
  let publish = 0;
  let activate = 0;

  for (const line of lines) {
    const [key, value] = util.splitColon(line);

    switch (key.toLowerCase()) {
      case 'private-key-format': {
        format = value.toLowerCase();
        break;
      }
      case 'algorithm': {
        const [left] = value.split(/[ \t]/);
        algorithm = util.parseU8(left);
        break;
      }
      case 'created': {
        created = util.parseTime(value);
        break;
      }
      case 'publish': {
        publish = util.parseTime(value);
        break;
      }
      case 'activate': {
        activate = util.parseTime(value);
        break;
      }
    }
  }

  if (algorithm === -1)
    throw new Error('Could not determine key algorithm.');

  return {
    format,
    algorithm,
    created,
    publish,
    activate
  };
};

keys.decodeRSA = function decodeRSA(str) {
  assert(typeof str === 'string');

  const lines = util.splitLines(str);
  const key = new RSAPrivateKey();

  let algorithm = -1;

  for (const line of lines) {
    const [name, value] = util.splitColon(line);

    switch (name.toLowerCase()) {
      case 'algorithm': {
        const [left] = value.split(/[ \t]/);
        const alg = util.parseU8(left);

        switch (alg) {
          case algs.RSAMD5:
          case algs.RSASHA1:
          case algs.RSASHA1NSEC3SHA1:
          case algs.RSASHA256:
          case algs.RSASHA512:
            break;
          default:
            throw new Error(`Not an RSA algorithm: ${algToString(alg)}.`);
        }

        algorithm = alg;

        break;
      }
      case 'modulus': {
        key.n = util.parseB64(value);
        break;
      }
      case 'publicexponent': {
        key.e = util.parseB64(value);
        break;
      }
      case 'privateexponent': {
        key.d = util.parseB64(value);
        break;
      }
      case 'prime1': {
        key.p = util.parseB64(value);
        break;
      }
      case 'prime2': {
        key.q = util.parseB64(value);
        break;
      }
      case 'exponent1': {
        key.dp = util.parseB64(value);
        break;
      }
      case 'exponent2': {
        key.dq = util.parseB64(value);
        break;
      }
      case 'coefficient': {
        key.qi = util.parseB64(value);
        break;
      }
    }
  }

  if (algorithm === -1)
    throw new Error('Could not determine key algorithm.');

  if (!rsa.privateVerify(key))
    throw new Error('Invalid RSA private key.');

  return [algorithm, key.encode()];
};

keys.decodeEC = function decodeEC(str) {
  assert(typeof str === 'string');

  const lines = util.splitLines(str);

  let key = null;
  let algorithm = -1;

  for (const line of lines) {
    const [name, value] = util.splitColon(line);

    switch (name.toLowerCase()) {
      case 'algorithm': {
        const [left] = value.split(/[ \t]/);
        const alg = util.parseU8(left);

        switch (alg) {
          case algs.ECC:
          case algs.ECCGOST:
          case algs.ECDSAP256SHA256:
          case algs.ECDSAP384SHA384:
          case algs.ED25519:
          case algs.ED448:
            break;
          default:
            throw new Error(`Not an RSA algorithm: ${algToString(alg)}.`);
        }

        algorithm = alg;

        break;
      }
      case 'privatekey': {
        key = util.parseB64(value);
        break;
      }
    }
  }

  if (algorithm === -1)
    throw new Error('Could not determine key algorithm.');

  if (!key)
    throw new Error('No private key found.');

  let valid = false;

  switch (algorithm) {
    case algs.ECDSAP256SHA256:
      valid = p256.privateKeyVerify(key);
      break;
    case algs.ECDSAP384SHA384:
      valid = p384.privateKeyVerify(key);
      break;
    case algs.ED25519:
      valid = ed25519.privateKeyVerify(key);
      break;
    default:
      throw new Error(`Unsupported key algorithm: ${algToString(algorithm)}.`);
  }

  if (!valid)
    throw new Error(`Invalid key for algorithm: ${algToString(algorithm)}.`);

  return [algorithm, key];
};
