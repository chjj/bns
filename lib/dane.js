/*!
 * dane.js - DANE for bns
 * Copyright (c) 2018, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bns
 *
 * Parts of this software are based on miekg/dns:
 *   https://github.com/miekg/dns/blob/master/dane.go
 *
 * Resources:
 *   https://tools.ietf.org/html/rfc6698
 */

'use strict';

const assert = require('assert');
const constants = require('./constants');
const crypto = require('./crypto');

const {
  usages,
  usagesByVal,
  selectors,
  selectorsByVal,
  matchingTypes,
  matchingTypesByVal
} = constants;

const dane = exports;

/*
 * DANE
 */

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
