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
const wire = require('./wire');
const crypto = require('./crypto');
const {types, Record} = wire;
const dane = exports;

/*
 * Constants
 */

const usages = {
  CAC: 0, // CA constraint
  SCC: 1, // Service certificate constraint
  TAA: 2, // Trust anchor assertion
  DIC: 3, // Domain-issued certificate
  // 4-254 are unassigned
  PRIVATE: 255 // Private Use
};

const usagesByVal = {
  [usages.CAC]: 'CAC',
  [usages.SCC]: 'SCC',
  [usages.TAA]: 'TAA',
  [usages.DIC]: 'DIC',
  [usages.PRIVATE]: 'PRIVATE'
};

const selectors = {
  FULL: 0, // Full Certificate
  SPKI: 1, // SubjectPublicKeyInfo
  // 2-254 are unassigned
  PRIVATE: 255 // Private Use
};

const selectorsByVal = {
  [selectors.FULL]: 'FULL',
  [selectors.SPKI]: 'SPKI',
  [selectors.PRIVATE]: 'PRIVATE'
};

const matchingTypes = {
  NONE: 0, // No hash used
  SHA256: 1,
  SHA512: 2,
  // 3-254 are unassigned
  PRIVATE: 255 // Private Use
};

const matchingTypesByVal = {
  [matchingTypes.NONE]: 'NONE',
  [matchingTypes.SHA256]: 'SHA256',
  [matchingTypes.SHA512]: 'SHA512',
  [matchingTypes.PRIVATE]: 'PRIVATE'
};

/*
 * DANE
 */

dane.create = function create(cert, selector, type) {
  assert(Buffer.isBuffer(cert));
  assert((selector & 0xffff) === selector);
  assert((type & 0xffff) === type);

  let data;

  switch (selector) {
    case selectors.FULL:
      data = getCert(cert);
      break;
    case selectors.SPKI:
      data = getPubkeyInfo(cert);
      break;
    default:
      throw new Error(`Unknown selector: ${selector}.`);
  }

  switch (type) {
    case matchingTypes.NONE:
      return data;
    case matchingTypes.SHA256:
      return crypto.sha256.digest(data);
    case matchingTypes.SHA512:
      return crypto.sha512.digest(data);
    default:
      throw new Error(`Unknown matching type: ${type}.`);
  }
};

dane.sign = function sign(rr, cert) {
  assert(rr instanceof Record);
  assert(rr.type === types.TLSA || rr.type === types.SMIMEA);

  const rd = rr.data;
  const selector = rd.selector;
  const type = rd.matchingType;

  rd.certificate = dane.create(cert, selector, type);

  return rr;
};

dane.verify = function verify(rr, cert) {
  assert(rr instanceof Record);
  assert(rr.type === types.TLSA || rr.type === types.SMIMEA);

  const rd = rr.data;
  const selector = rd.selector;
  const type = rd.matchingType;
  const data = dane.create(cert, selector, type);

  return rd.certificate.equals(data);
};

/*
 * Helpers
 */

function getCert(data) {
  let off = 0;
  let size;

  [off, size] = read(data, off);

  assert(off + size <= data.length);

  return data.slice(off, off + size);
}

function getPubkeyInfo(data) {
  let off = 0;
  let size;

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
  [off, size] = read(data, off);

  assert(off + size <= data.length);

  return data.slice(off, off + size);
}

function tag(data, off, expect, explicit) {
  assert(off < data.length);

  const type = data[off];

  if (type !== expect) {
    if (explicit)
      return [off, 0];
    throw new Error(`Expected type: ${expect}.`);
  }

  off += 1;

  assert(off < data.length);

  let size = data[off++];

  if ((size & 0x80) === 0)
    return [off, size];

  const bytes = size & 0x7f;

  if (bytes > 3)
    throw new Error('Length octet is too long.');

  size = 0;

  for (let i = 0; i < bytes; i++) {
    size <<= 8;

    assert(off < data.length);

    size |= data[off++];
  }

  return [off, size];
}

function read(data, off) {
  return tag(data, off, 0x10, false);
}

function seq(data, off) {
  return read(data, off)[0];
}

function skip(data, off) {
  const [offset, size] = read(data, off);
  return offset + size;
}

function int(data, off) {
  const [offset, size] = tag(data, off, 0x02, false);
  return offset + size;
}

function xint(data, off) {
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
