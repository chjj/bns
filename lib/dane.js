/*!
 * dane.js - DANE for bns
 * Copyright (c) 2018, Christopher Jeffrey (MIT License).
 * https://github.com/chjj/bns
 *
 * Parts of this software are based on miekg/dns:
 *   https://github.com/miekg/dns/blob/master/dane.go
 *
 * Resources:
 *   https://tools.ietf.org/html/rfc6698
 */

'use strict';

const assert = require('bsert');
const constants = require('./constants');
const crypto = require('./internal/crypto');
const util = require('./util');

const {
  usages,
  usagesByVal,
  selectors,
  selectorsByVal,
  matchingTypes,
  matchingTypesByVal
} = constants;

/*
 * DANE
 */

const dane = exports;

dane.select = function select(cert, selector) {
  assert(Buffer.isBuffer(cert));
  assert((selector & 0xff) === selector);

  switch (selector) {
    case selectors.FULL:
      return getCert(cert);
    case selectors.SPKI:
      return getPubkeyInfo(cert);
  }

  return null;
};

dane.hash = function hash(data, matchingType) {
  assert(Buffer.isBuffer(data));
  assert((matchingType & 0xff) === matchingType);

  switch (matchingType) {
    case matchingTypes.NONE:
      return data;
    case matchingTypes.SHA256:
      return crypto.sha256.digest(data);
    case matchingTypes.SHA512:
      return crypto.sha512.digest(data);
  }

  return null;
};

dane.sign = function sign(cert, selector, matchingType) {
  const data = dane.select(cert, selector);

  if (!data)
    return null;

  const hash = dane.hash(data, matchingType);

  if (!hash)
    return null;

  return hash;
};

dane.verify = function verify(cert, selector, matchingType, certificate) {
  const hash = dane.sign(cert, selector, matchingType);

  if (!hash)
    return false;

  return hash.equals(certificate);
};

dane.encodeEmail = function encodeEmail(email, tag, bits) {
  assert(typeof email === 'string');
  assert(email.length >= 3 && email.length <= 320);

  const index = email.indexOf('@');
  assert(index !== -1);

  const local = email.substring(0, index);
  const name = email.substring(index + 1);

  return dane.encodeName(name, tag, local, bits);
};

dane.hashLocal = function hashLocal(local, bits, enc) {
  if (bits == null)
    bits = 256;

  if (enc == null)
    enc = null;

  assert(typeof local === 'string');
  assert(local.length <= 64);
  assert(local.indexOf('@') === -1);
  assert(typeof bits === 'number');
  assert(bits === 224 || bits === 256);
  assert(enc === null || enc === 'hex');

  const raw = Buffer.from(local, 'utf8');
  const hash = bits === 224
    ? crypto.sha224.digest(raw)
    : crypto.sha256.digest(raw);

  if (enc === 'hex')
    return hash.toString('hex', 0, 28);

  return hash.slice(0, 28);
};

dane.encodeName = function encodeName(name, tag, local, bits) {
  assert(util.isName(name));
  assert(name.length === 0 || name[0] !== '_');
  assert(util.isName(tag));
  assert(tag.length >= 1 && tag.length <= 62);
  assert(tag[0] !== '_');
  assert(tag.indexOf('.') === -1);

  if (name === '.')
    name = '';

  const hash = dane.hashLocal(local, bits, 'hex');
  const encoded = util.fqdn(`${hash}._${tag}.${name}`);

  assert(util.isName(encoded));

  return encoded;
};

dane.decodeName = function decodeName(name, tag) {
  assert(util.isName(name));
  assert(util.isName(tag));
  assert(tag.length >= 1 && tag.length <= 62);
  assert(tag[0] !== '_');
  assert(tag.indexOf('.') === -1);

  const labels = util.split(name);

  assert(labels.length >= 3);

  const hex = util.label(name, labels, 0);
  const part = util.label(name, labels, 1);

  assert(hex.length >= 1);
  assert(part.length >= 2);
  assert(part[0] === '_');

  if (part.toLowerCase() !== `_${tag}`)
    throw new Error('Invalid DANE name.');

  if (hex.length !== 56)
    throw new Error('Invalid DANE hash.');

  const hash = Buffer.from(hex, 'hex');

  if (hash.length !== 28)
    throw new Error('Invalid DANE hash.');

  return {
    name: util.fqdn(util.from(name, labels, 2)),
    hash: hash
  };
};

dane.isName = function isName(name, tag) {
  assert(util.isName(name));
  assert(util.isName(tag));
  assert(tag.length >= 1 && tag.length <= 62);
  assert(tag[0] !== '_');
  assert(tag.indexOf('.') === -1);

  try {
    dane.decodeName(name, tag);
    return true;
  } catch (e) {
    return false;
  }
};

/*
 * Helpers
 */

function getCert(data) {
  const size = gauge(data, 0);
  assert(size <= data.length);
  return data.slice(0, size);
}

function getPubkeyInfo(data) {
  let off = 0;

  // cert
  off = seq(data, off);

  // tbs
  off = seq(data, off);

  // version
  off = xint(data, off);

  // serial
  off = int(data, off);

  // alg ident
  off = skip(data, off);

  // issuer
  off = skip(data, off);

  // validity
  off = skip(data, off);

  // subject
  off = skip(data, off);

  // pubkeyinfo
  const size = gauge(data, off);

  assert(off + size <= data.length);

  return data.slice(off, off + size);
}

function tag(data, off, expect, explicit) {
  assert(off < data.length);

  const start = off;

  let type = data[off++];

  const primitive = (type & 0x20) === 0;

  if ((type & 0x1f) === 0x1f) {
    let oct = type;
    type = 0;
    while ((oct & 0x80) === 0x80) {
      assert(off < data.length);
      oct = data[off++];
      type <<= 7;
      type |= oct & 0x7f;
    }
  } else {
    type &= 0x1f;
  }

  if (type !== expect) {
    if (explicit)
      return [start, 0];
    throw new Error(`Expected type: ${expect}. Got: ${type}.`);
  }

  assert(off < data.length);

  let size = data[off++];

  if (!primitive && size === 0x80)
    throw new Error('Indefinite size.');

  if ((size & 0x80) === 0)
    return [off, size];

  const bytes = size & 0x7f;

  if (bytes > 3)
    throw new Error('Length octet is too long.');

  size = 0;

  for (let i = 0; i < bytes; i++) {
    assert(off < data.length);
    size <<= 8;
    size |= data[off++];
  }

  // Return:
  // [0]: Offset after the header.
  // [1]: Size of bytes to read next.
  return [off, size];
}

function read(data, off) {
  // Read seq-header, update offset to after header.
  return tag(data, off, 0x10, false);
}

function gauge(data, off) {
  // Get total size of seq-header + data.
  const [pos, size] = read(data, off);
  return (pos - off) + size;
}

function seq(data, off) {
  // Read seq-header, return offset after header.
  return read(data, off)[0];
}

function skip(data, off) {
  // Read seq-header, return offset after header+data.
  const [offset, size] = read(data, off);
  return offset + size;
}

function int(data, off) {
  // Read int-header, return offset after header+data.
  const [offset, size] = tag(data, off, 0x02, false);
  return offset + size;
}

function xint(data, off) {
  // Read int-header (explicit), return offset after header+data.
  const [offset, size] = tag(data, off, 0x00, true);
  return offset + size;
}

/*
 * Expose
 */

dane.usages = usages;
dane.usagesByVal = usagesByVal;
dane.selectors = selectors;
dane.selectorsByVal = selectorsByVal;
dane.matchingTypes = matchingTypes;
dane.matchingTypesByVal = matchingTypesByVal;
