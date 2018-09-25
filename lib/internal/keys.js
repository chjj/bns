/*!
 * keys.js - DNSSEC keys for bns
 * Copyright (c) 2018, Christopher Jeffrey (MIT License).
 * https://github.com/chjj/bns
 */

'use strict';

const assert = require('bsert');
const Path = require('path');
const fs = require('bfile');
const dsa = require('bcrypto/lib/dsa');
const rsa = require('bcrypto/lib/rsa');
const p256 = require('bcrypto/lib/p256');
const p384 = require('bcrypto/lib/p384');
const ed25519 = require('bcrypto/lib/ed25519');
const crypto = require('./crypto');
const constants = require('../constants');
const util = require('../util');
const wire = require('../wire');
const {types, Record} = wire;

const {
  algs,
  algToString
} = constants;

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

keys.createPrivate = function createPrivate(algorithm, bits, exp) {
  assert((algorithm & 0xff) === algorithm);

  switch (algorithm) {
    case algs.DSA:
    case algs.DSANSEC3SHA1: {
      return crypto.generateDSA(bits);
    }
    case algs.RSAMD5:
    case algs.RSASHA1:
    case algs.RSASHA1NSEC3SHA1:
    case algs.RSASHA256:
    case algs.RSASHA512: {
      return crypto.generateRSA(bits, exp);
    }
    case algs.ECDSAP256SHA256: {
      return crypto.generateP256();
    }
    case algs.ECDSAP384SHA384: {
      return crypto.generateP384();
    }
    case algs.ED25519: {
      return crypto.generateED25519();
    }
    case algs.ED448: {
      return crypto.generateED448();
    }
    default: {
      throw new Error(`Unsupported algorithm: ${algToString(algorithm)}.`);
    }
  }
};

keys.createPrivateAsync = async function createPrivateAsync(algorithm, bits, exp) {
  assert((algorithm & 0xff) === algorithm);

  switch (algorithm) {
    case algs.DSA:
    case algs.DSANSEC3SHA1: {
      return crypto.generateDSAAsync(bits);
    }
    case algs.RSAMD5:
    case algs.RSASHA1:
    case algs.RSASHA1NSEC3SHA1:
    case algs.RSASHA256:
    case algs.RSASHA512: {
      return crypto.generateRSAAsync(bits, exp);
    }
    case algs.ECDSAP256SHA256: {
      return crypto.generateP256();
    }
    case algs.ECDSAP384SHA384: {
      return crypto.generateP384();
    }
    case algs.ED25519: {
      return crypto.generateED25519();
    }
    case algs.ED448: {
      return crypto.generateED448();
    }
    default: {
      throw new Error(`Unsupported algorithm: ${algToString(algorithm)}.`);
    }
  }
};

keys.createPublic = function createPublic(algorithm, raw) {
  assert((algorithm & 0xff) === algorithm);
  assert(Buffer.isBuffer(raw));

  switch (algorithm) {
    case algs.DSA:
    case algs.DSANSEC3SHA1: {
      return crypto.createDSA(raw);
    }
    case algs.RSAMD5:
    case algs.RSASHA1:
    case algs.RSASHA1NSEC3SHA1:
    case algs.RSASHA256:
    case algs.RSASHA512: {
      return crypto.createRSA(raw);
    }
    case algs.ECDSAP256SHA256: {
      return crypto.createP256(raw);
    }
    case algs.ECDSAP384SHA384: {
      return crypto.createP384(raw);
    }
    case algs.ED25519: {
      return crypto.createED25519(raw);
    }
    case algs.ED448: {
      return crypto.createED448(raw);
    }
    default: {
      throw new Error(`Unsupported algorithm: ${algToString(algorithm)}.`);
    }
  }
};

keys.encodePrivate = function encodePrivate(algorithm, raw, time) {
  if (time == null)
    time = util.now();

  assert((algorithm & 0xff) === algorithm);
  assert(Buffer.isBuffer(raw));
  assert(Number.isSafeInteger(time) && time >= 0);

  switch (algorithm) {
    case algs.DSA:
    case algs.DSANSEC3SHA1: {
      return keys.encodeDSA(algorithm, raw, time);
    }
    case algs.RSAMD5:
    case algs.RSASHA1:
    case algs.RSASHA1NSEC3SHA1:
    case algs.RSASHA256:
    case algs.RSASHA512:
      return keys.encodeRSA(algorithm, raw, time);
    case algs.ECDSAP256SHA256:
    case algs.ECDSAP384SHA384:
    case algs.ED25519:
    case algs.ED448:
      return keys.encodeEC(algorithm, raw, time);
    default:
      throw new Error(`Unsupported algorithm: ${algToString(algorithm)}.`);
  }
};

keys.encodeDSA = function encodeDSA(algorithm, raw, time) {
  assert((algorithm & 0xff) === algorithm);
  assert(Buffer.isBuffer(raw));

  const key = dsa.privateKeyImport(raw);
  const now = util.serializeTime(time);

  return [
    `Private-key-format: ${VERSION}`,
    `Algorithm: ${algorithm} (${algToString(algorithm)})`,
    `Prime(p): ${key.p.toString('base64')}`,
    `Subprime(q): ${key.q.toString('base64')}`,
    `Base(g): ${key.g.toString('base64')}`,
    `Private_value(x): ${key.x.toString('base64')}`,
    `Public_value(y): ${key.y.toString('base64')}`,
    `Created: ${now}`,
    `Publish: ${now}`,
    `Activate: ${now}`
  ].join('\n');
};

keys.encodeRSA = function encodeRSA(algorithm, raw, time) {
  assert((algorithm & 0xff) === algorithm);
  assert(Buffer.isBuffer(raw));

  const key = rsa.privateKeyImport(raw);
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
    case algs.DSA:
    case algs.DSANSEC3SHA1:
      return keys.decodeDSA(str);
    case algs.RSAMD5:
    case algs.RSASHA1:
    case algs.RSASHA1NSEC3SHA1:
    case algs.RSASHA256:
    case algs.RSASHA512:
      return keys.decodeRSA(str);
    case algs.ECDSAP256SHA256:
    case algs.ECDSAP384SHA384:
    case algs.ED25519:
    case algs.ED448:
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

keys.decodeDSA = function decodeDSA(str) {
  assert(typeof str === 'string');

  const lines = util.splitLines(str);
  const key = new dsa.DSAPrivateKey();

  let algorithm = -1;

  for (const line of lines) {
    const [name, value] = util.splitColon(line);

    switch (name.toLowerCase()) {
      case 'algorithm': {
        const [left] = value.split(/[ \t]/);
        const alg = util.parseU8(left);

        switch (alg) {
          case algs.DSA:
          case algs.DSANSEC3SHA1:
            break;
          default:
            throw new Error(`Not a DSA algorithm: ${algToString(alg)}.`);
        }

        algorithm = alg;

        break;
      }
      case 'prime(p)': {
        const p = util.parseB64(value);
        key.setP(p);
        break;
      }
      case 'subprime(q)': {
        const q = util.parseB64(value);
        key.setQ(q);
        break;
      }
      case 'base(g)': {
        const g = util.parseB64(value);
        key.setG(g);
        break;
      }
      case 'private_value(x)': {
        const x = util.parseB64(value);
        key.setX(x);
        break;
      }
      case 'public_value(y)': {
        const y = util.parseB64(value);
        key.setY(y);
        break;
      }
    }
  }

  if (algorithm === -1)
    throw new Error('Could not determine key algorithm.');

  if (!dsa.privateKeyVerify(key))
    throw new Error('Invalid DSA private key.');

  return [algorithm, dsa.privateKeyExport(key)];
};

keys.decodeRSA = function decodeRSA(str) {
  assert(typeof str === 'string');

  const lines = util.splitLines(str);
  const key = new rsa.RSAPrivateKey();

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
        const n = util.parseB64(value);
        key.setN(n);
        break;
      }
      case 'publicexponent': {
        const e = util.parseB64(value);
        key.setE(e);
        break;
      }
      case 'privateexponent': {
        const d = util.parseB64(value);
        key.setD(d);
        break;
      }
      case 'prime1': {
        const p = util.parseB64(value);
        key.setP(p);
        break;
      }
      case 'prime2': {
        const q = util.parseB64(value);
        key.setQ(q);
        break;
      }
      case 'exponent1': {
        const dp = util.parseB64(value);
        key.setDP(dp);
        break;
      }
      case 'exponent2': {
        const dq = util.parseB64(value);
        key.setDQ(dq);
        break;
      }
      case 'coefficient': {
        const qi = util.parseB64(value);
        key.setQI(qi);
        break;
      }
    }
  }

  if (algorithm === -1)
    throw new Error('Could not determine key algorithm.');

  if (!rsa.privateKeyVerify(key))
    throw new Error('Invalid RSA private key.');

  return [algorithm, rsa.privateKeyExport(key)];
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
            throw new Error(`Not an EC algorithm: ${algToString(alg)}.`);
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
    case algs.ED448:
      valid = false;
      break;
    default:
      throw new Error(`Unsupported key algorithm: ${algToString(algorithm)}.`);
  }

  if (!valid)
    throw new Error(`Invalid key for algorithm: ${algToString(algorithm)}.`);

  return [algorithm, key];
};

keys.readPrivate = function readPrivate(dir, name, algorithm, keyTag) {
  assert(typeof dir === 'string');

  if (typeof name !== 'string') {
    const rr = name;

    assert(rr instanceof Record);

    const rd = rr.data;

    if (rr.type === types.DNSKEY) {
      name = rr.name;
      algorithm = rd.algorithm;
      keyTag = rd.keyTag();
    } else if (rr.type === types.DS) {
      name = rr.name;
      algorithm = rd.algorithm;
      keyTag = rd.keyTag;
    } else {
      throw new TypeError('Not a DNSKEY or DS record.');
    }
  }

  const file = keys.privFile(name, algorithm, keyTag);
  const str = readFile(dir, file, 'utf8');

  if (!str)
    return null;

  const [alg, priv] = keys.decodePrivate(str);

  if (alg !== algorithm)
    throw new Error('Algorithm mismatch for private key.');

  return priv;
};

keys.readPrivateAsync = async function readPrivateAsync(dir, name, algorithm, keyTag) {
  assert(typeof dir === 'string');

  if (typeof name !== 'string') {
    const rr = name;

    assert(rr instanceof Record);

    const rd = rr.data;

    if (rr.type === types.DNSKEY) {
      name = rr.name;
      algorithm = rd.algorithm;
      keyTag = rd.keyTag();
    } else if (rr.type === types.DS) {
      name = rr.name;
      algorithm = rd.algorithm;
      keyTag = rd.keyTag;
    } else {
      throw new TypeError('Not a DNSKEY or DS record.');
    }
  }

  const file = keys.privFile(name, algorithm, keyTag);
  const str = await readFileAsync(dir, file, 'utf8');

  if (!str)
    return null;

  const [alg, priv] = keys.decodePrivate(str);

  if (alg !== algorithm)
    throw new Error('Algorithm mismatch for private key.');

  return priv;
};

keys.readPublic = function readPublic(dir, name, algorithm, keyTag) {
  assert(typeof dir === 'string');

  if (typeof name !== 'string') {
    const rr = name;

    assert(rr instanceof Record);

    const rd = rr.data;

    if (rr.type === types.DNSKEY) {
      name = rr.name;
      algorithm = rd.algorithm;
      keyTag = rd.keyTag();
    } else if (rr.type === types.DS) {
      name = rr.name;
      algorithm = rd.algorithm;
      keyTag = rd.keyTag;
    } else {
      throw new TypeError('Not a DNSKEY or DS record.');
    }
  }

  const file = keys.pubFile(name, algorithm, keyTag);
  const str = readFile(dir, file, 'utf8');

  if (!str)
    return null;

  const key = Record.fromString(str);

  if (key.type !== types.DNSKEY)
    throw new Error('Type mismatch for public key.');

  if (key.data.keyTag() !== keyTag)
    throw new Error('DS mismatch for public key.');

  return key;
};

keys.readPublicAsync = async function readPublicAsync(dir, name, algorithm, keyTag) {
  assert(typeof dir === 'string');

  if (typeof name !== 'string') {
    const rr = name;

    assert(rr instanceof Record);

    const rd = rr.data;

    if (rr.type === types.DNSKEY) {
      name = rr.name;
      algorithm = rd.algorithm;
      keyTag = rd.keyTag();
    } else if (rr.type === types.DS) {
      name = rr.name;
      algorithm = rd.algorithm;
      keyTag = rd.keyTag;
    } else {
      throw new TypeError('Not a DNSKEY or DS record.');
    }
  }

  const file = keys.pubFile(name, algorithm, keyTag);
  const str = await readFileAsync(dir, file, 'utf8');

  if (!str)
    return null;

  const key = Record.fromString(str);

  if (key.type !== types.DNSKEY)
    throw new Error('Type mismatch for public key.');

  if (key.data.keyTag() !== keyTag)
    throw new Error('DS mismatch for public key.');

  return key;
};

keys.writeKeys = function writeKeys(dir, rr, priv, time) {
  keys.writePrivate(dir, rr, priv, time);
  keys.writePublic(dir, rr);
};

keys.writeKeysAsync = async function writeKeysAsync(dir, rr, priv, time) {
  await keys.writePrivateAsync(dir, rr, priv, time);
  await keys.writePublicAsync(dir, rr);
};

keys.writePrivate = function writePrivate(dir, rr, priv, time) {
  assert(typeof dir === 'string');
  assert(rr instanceof Record);
  assert(rr.type === types.DNSKEY);
  assert(Buffer.isBuffer(priv));

  const rd = rr.data;
  const file = keys.privFile(rr.name, rd.algorithm, rd.keyTag());
  const txt = keys.encodePrivate(rd.algorithm, priv, time);

  writeFile(dir, file, txt + '\n', 'utf8');
};

keys.writePrivateAsync = async function writePrivateAsync(dir, rr, priv, time) {
  assert(typeof dir === 'string');
  assert(rr instanceof Record);
  assert(rr.type === types.DNSKEY);
  assert(Buffer.isBuffer(priv));

  const rd = rr.data;
  const file = keys.privFile(rr.name, rd.algorithm, rd.keyTag());
  const txt = keys.encodePrivate(rd.algorithm, priv, time);

  return writeFileAsync(dir, file, txt + '\n', 'utf8');
};

keys.writePublic = function writePublic(dir, rr) {
  assert(typeof dir === 'string');
  assert(rr instanceof Record);
  assert(rr.type === types.DNSKEY);

  const rd = rr.data;
  const file = keys.pubFile(rr.name, rd.algorithm, rd.keyTag());
  const txt = rr.toString();

  writeFile(dir, file, txt + '\n', 'utf8');
};

keys.writePublicAsync = async function writePublicAsync(dir, rr) {
  assert(typeof dir === 'string');
  assert(rr instanceof Record);
  assert(rr.type === types.DNSKEY);

  const rd = rr.data;
  const file = keys.pubFile(rr.name, rd.algorithm, rd.keyTag());
  const txt = rr.toString();

  return writeFileAsync(dir, file, txt + '\n', 'utf8');
};

/*
 * Helpers
 */

function readFile(dir, file, enc) {
  assert(typeof dir === 'string');
  assert(typeof file === 'string');
  assert(enc == null || typeof enc === 'string');

  const path = Path.resolve(dir, file);

  try {
    return fs.readFileSync(path, enc);
  } catch (e) {
    if (e.code === 'ENOENT')
      return null;
    throw e;
  }
}

async function readFileAsync(dir, file, enc) {
  assert(typeof dir === 'string');
  assert(typeof file === 'string');
  assert(enc == null || typeof enc === 'string');

  const path = Path.resolve(dir, file);

  try {
    return await fs.readFile(path, enc);
  } catch (e) {
    if (e.code === 'ENOENT')
      return null;
    throw e;
  }
}

function writeFile(dir, file, txt, enc) {
  assert(typeof dir === 'string');
  assert(typeof file === 'string');
  assert(typeof txt === 'string');
  assert(enc == null || typeof enc === 'string');

  const path = Path.resolve(dir, file);

  fs.writeFileSync(path, txt, enc);
}

async function writeFileAsync(dir, file, txt, enc) {
  assert(typeof dir === 'string');
  assert(typeof file === 'string');
  assert(typeof txt === 'string');
  assert(enc == null || typeof enc === 'string');

  const path = Path.resolve(dir, file);

  return fs.writeFile(path, txt, enc);
}
