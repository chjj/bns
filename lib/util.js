/*!
 * util.js - utils for bns
 * Copyright (c) 2018, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bns
 *
 * Parts of this software are based on miekg/dns and golang/go:
 *   https://github.com/miekg/dns/blob/master/dnssec.go
 */

'use strict';

const util = exports;

util.splitName = function splitName(s) {
  if (s.length === 0)
    return [];

  const idx = util.split(s);
  const labels = [];

  let fend = 0;
  let begin = 0;

  if (s[s.length - 1] === '.')
    fend = s.length - 1;
  else
    fend = s.length;

  switch (idx.length) {
    case 0: {
      return [];
    }
    case 1: {
      break;
    }
    default: {
      let end = 0;
      for (let i = 1; i < idx.length; i++) {
        end = idx[i];
        labels.push(s.substring(begin, end - 1));
        begin = end;
      }
      break;
    }
  }

  labels.push(s.substring(begin, fend));

  return labels;
};

util.compareName = function compareName(s1, s2) {
  let n = 0;

  if (s1 === '.' || s2 === '.')
    return 0;

  const l1 = util.split(s1);
  const l2 = util.split(s2);

  let j1 = l1.length - 1;
  let i1 = l1.length - 2;

  let j2 = l2.length - 1;
  let i2 = l2.length - 2;

  const a = s1.substring(l1[j1]);
  const b = s2.substring(l2[j2]);

  if (a !== b)
    return n;

  n += 1;

  for (;;) {
    if (i1 < 0 || i2 < 0)
      break;

    const a = s1.substring(l1[i1], l1[j1]);
    const b = s2.substring(l2[i2], l2[j2]);

    if (a !== b)
      break;

    n += 1;

    j1 -= 1;
    i1 -= 1;

    j2 -= 1;
    i2 -= 1;
  }

  return n;
};

util.countLabel = function countLabel(s) {
  let labels = 0;

  if (s === '.')
    return labels;

  let off = 0;
  let end = false;

  for (;;) {
    [off, end] = util.nextLabel(s, off);

    labels += 1;

    if (end)
      break;
  }

  return labels;
};

util.split = function split(s) {
  if (s === '.')
    return [];

  const idx = [0];

  let off = 0;
  let end = false;

  for (;;) {
    [off, end] = util.nextLabel(s, off);

    if (end)
      break;

    idx.push(off);
  }

  return idx;
};

util.nextLabel = function nextLabel(s, off) {
  let quote = false;
  let i = 0;

  for (i = off; i < s.length - 1; i++) {
    switch (s[i]) {
      case '\\':
        quote = !quote;
        break;
      case '.':
        if (quote) {
          quote = !quote;
          continue;
        }
        return [i + 1, false];
      default:
        quote = false;
        break;
    }
  }

  return [i + 1, true];
};

util.prevLabel = function prevLabel(s, n) {
  if (n === 0)
    return [s.length, false];

  const lab = util.split(s);

  if (lab.length === 0) // NIL
    return [0, true];

  if (n > lab.length)
    return [0, true];

  return [lab[lab.length - n], false];
};

util.equal = function equal(a, b) {
  if (a.length !== b.length)
    return false;

  return a.toLowerCase() === b.toLowerCase();
};

util.isSubdomain = function isSubdomain(parent, child) {
  return util.compareName(parent, child) === util.countLabel(parent);
};

util.isRRSet = function isRRSet(rrset) {
  if (rrset.length === 0)
    return false;

  if (rrset.length === 1)
    return true;

  const type = rrset[0].type;
  const class_ = rrset[0].class;
  const name = rrset[0].name;

  for (let i = 1; i < rrset.length; i++) {
    const rr = rrset[i];

    if (rr.type !== type
        || rr.class !== class_
        || rr.name !== name) {
      return false;
    }
  }

  return true;
};

util.filterSet = function filterSet(records, ...types) {
  const map = new Set(types);
  const out = [];

  for (const rr of records) {
    if (!map.has(rr.type))
      out.push(rr);
  }

  return out;
};

util.extractSet = function extractSet(records, name, ...types) {
  const map = new Set(types);
  const out = [];

  for (const rr of records) {
    if (map.has(rr.type)) {
      if (name !== '' && name !== rr.name)
        continue;
      out.push(rr);
    }
  }

  return out;
};

util.hasAll = function hasAll(records, type) {
  for (const rr of records) {
    if (rr.type !== type)
      return false;
  }
  return true;
};

util.random = function random(n) {
  return Math.floor(Math.random() * n);
};

util.randomItem = function randomItem(items) {
  return items[util.random(items.length)];
};

util.now = function now() {
  return Math.floor(Date.now() / 1000);
};

util.dir = function dir(obj) {
  console.dir(obj, {
    depth: 20,
    colors: true,
    customInspect: true
  });
};
