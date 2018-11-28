/*!
 * nsec3.js - NSEC3 for bns
 * Copyright (c) 2018, Christopher Jeffrey (MIT License).
 * https://github.com/chjj/bns
 *
 * Parts of this software are based on miekg/dns and golang/go:
 *   https://github.com/miekg/dns/blob/master/nsecx.go
 *
 * Parts of this software are based on solvere:
 *   https://github.com/rolandshoemaker/solvere
 */

'use strict';

const assert = require('bsert');
const base32 = require('bs32');
const constants = require('./constants');
const crypto = require('./internal/crypto');
const encoding = require('./encoding');
const wire = require('./wire');
const util = require('./util');

const {
  types,
  nsecHashes,
  nsecHashesByVal
} = constants;

const {
  hasType,
  packName
} = encoding;

const {
  Question,
  Record
} = wire;

/*
 * Constants
 */

const MAX_ITERATIONS = 512;

/*
 * NSEC3
 */

const nsec3 = exports;

nsec3.hashName = function hashName(name, ha, iter, salt) {
  assert(typeof name === 'string');
  assert((ha & 0xff) === ha);
  assert((iter & 0xffff) === iter);
  assert(Buffer.isBuffer(salt));

  // DoS vector.
  if (iter > MAX_ITERATIONS)
    return null;

  const nameRaw = packName(name.toLowerCase());
  const saltRaw = salt;

  let hash = null;

  switch (ha) {
    case nsecHashes.SHA1:
      hash = crypto.sha1;
      break;
  }

  if (!hash)
    return null;

  let nameHash = hash.multi(nameRaw, saltRaw);

  for (let i = 0; i < iter; i++)
    nameHash = hash.multi(nameHash, saltRaw);

  return nameHash;
};

nsec3.cover = function cover(rr, name) {
  assert(rr instanceof Record);
  assert(rr.type === types.NSEC3);

  const rd = rr.data;
  const nameHash = nsec3.hashName(name, rd.hash, rd.iterations, rd.salt);

  if (!nameHash)
    return false;

  const owner = rr.name;
  const label = util.split(owner);

  if (label.length < 2)
    return false;

  const owner32 = owner.substring(0, label[1] - 1);
  const ownerZone = owner.substring(label[1]);
  const ownerHash = decodeHex(owner32);

  if (!ownerHash)
    return false;

  if (ownerHash.length !== nameHash.length)
    return false;

  if (!util.isSubdomain(ownerZone, name))
    return false;

  const nextHash = rd.nextDomain;

  if (nextHash.length !== nameHash.length)
    return false;

  if (ownerHash.equals(nextHash))
    return false;

  if (ownerHash.compare(nextHash) > 0) {
    if (nameHash.compare(ownerHash) > 0)
      return true;
    return nameHash.compare(nextHash) < 0;
  }

  if (nameHash.compare(ownerHash) < 0)
    return false;

  return nameHash.compare(nextHash) < 0;
};

nsec3.match = function match(rr, name) {
  assert(rr instanceof Record);
  assert(rr.type === types.NSEC3);

  const rd = rr.data;
  const nameHash = nsec3.hashName(name, rd.hash, rd.iterations, rd.salt);

  if (!nameHash)
    return false;

  const owner = rr.name;
  const label = util.split(owner);

  if (label.length < 2)
    return false;

  const owner32 = owner.substring(0, label[1] - 1);
  const ownerZone = owner.substring(label[1]);
  const ownerHash = decodeHex(owner32);

  if (!ownerHash)
    return false;

  if (ownerHash.length !== nameHash.length)
    return false;

  if (!util.isSubdomain(ownerZone, name))
    return false;

  if (ownerHash.equals(nameHash))
    return true;

  return false;
};

nsec3.findClosestEncloser = function findClosestEncloser(name, nsec) {
  assert(typeof name === 'string');
  assert(Array.isArray(nsec));

  const label = util.split(name);

  let nc = name;

  for (let i = 0; i < label.length; i++) {
    const z = name.substring(label[i]);
    const bm = nsec3.findMatching(z, nsec);

    if (!bm)
      continue;

    if (i !== 0)
      nc = name.substring(label[i - 1]);

    return [z, nc];
  }

  return ['', ''];
};

nsec3.findMatching = function findMatching(name, nsec) {
  assert(typeof name === 'string');
  assert(Array.isArray(nsec));

  for (const rr of nsec) {
    if (nsec3.match(rr, name))
      return rr.data.typeBitmap;
  }

  return null; // NSEC missing coverage
};

nsec3.findCoverer = function findCoverer(name, nsec) {
  assert(typeof name === 'string');
  assert(Array.isArray(nsec));

  for (const rr of nsec) {
    if (nsec3.cover(rr, name)) {
      const rd = rr.data;
      return [rd.typeBitmap, (rd.flags & 1) === 1];
    }
  }

  return [null, false]; // NSEC missing coverage
};

nsec3.verifyNameError = function verifyNameError(qs, nsec) {
  const [ce, nc] = nsec3.findClosestEncloser(qs.name, nsec);

  if (ce === '')
    return false; // NSEC missing coverage

  const [cv] = nsec3.findCoverer(nc, nsec);

  if (!cv)
    return false; // NSEC missing coverage

  return true;
};

nsec3.verifyNoData = function verifyNoData(qs, nsec) {
  assert(qs instanceof Question);
  assert(Array.isArray(nsec));

  const bm = nsec3.findMatching(qs.name, nsec);

  if (!bm) {
    if (qs.type !== types.DS)
      return false; // NSEC missing coverage

    const [ce, nc] = nsec3.findClosestEncloser(qs.name, nsec);

    if (ce === '')
      return false; // NSEC missing coverage

    const [b, optOut] = nsec3.findCoverer(nc, nsec);

    if (!b)
      return false; // NSEC missing coverage

    if (!optOut)
      return false; // NSEC opt out

    return true;
  }

  if (hasType(bm, qs.type))
    return false; // NSEC type exists

  if (hasType(bm, types.CNAME))
    return false; // NSEC type exists

  return true;
};

nsec3.verifyDelegation = function verifyDelegation(delegation, nsec) {
  const bm = nsec3.findMatching(delegation, nsec);

  if (!bm) {
    const [ce, nc] = nsec3.findClosestEncloser(delegation, nsec);

    if (ce === '')
      return false; // NSEC missing coverage

    const [b, optOut] = nsec3.findCoverer(nc, nsec);

    if (!b)
      return false; // NSEC missing coverage

    if (!optOut)
      return false; // NSEC opt out

    return true;
  }

  if (!hasType(bm, types.NS))
    return false; // NSEC NS missing

  if (hasType(bm, types.DS))
    return false; // NSEC bad delegation

  if (hasType(bm, types.SOA))
    return false; // NSEC bad delegation

  return true;
};

/*
 * Helpers
 */

function decodeHex(str) {
  try {
    return base32.decodeHex(str);
  } catch (e) {
    return null;
  }
}

/*
 * Expose
 */

nsec3.hashes = nsecHashes;
nsec3.hashesByVal = nsecHashesByVal;
