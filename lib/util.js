/*!
 * util.js - utils for bns
 * Copyright (c) 2018, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bns
 *
 * Parts of this software are based on miekg/dns and golang/go:
 *   https://github.com/miekg/dns/blob/master/labels.go
 *   https://github.com/miekg/dns/blob/master/dnsutil/util.go
 */

'use strict';

const assert = require('assert');
const IP = require('binet');
const {sizeName} = require('./encoding');
const util = exports;

util.splitName = function splitName(s) {
  assert(typeof s === 'string');

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
  assert(typeof s1 === 'string');
  assert(typeof s2 === 'string');

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

  if (!util.equal(a, b))
    return n;

  n += 1;

  for (;;) {
    if (i1 < 0 || i2 < 0)
      break;

    const a = s1.substring(l1[i1], l1[j1]);
    const b = s2.substring(l2[i2], l2[j2]);

    if (!util.equal(a, b))
      break;

    n += 1;

    j1 -= 1;
    i1 -= 1;

    j2 -= 1;
    i2 -= 1;
  }

  return n;
};

util.countLabels = function countLabels(s) {
  assert(typeof s === 'string');

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
  assert(typeof s === 'string');

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
  assert(typeof s === 'string');
  assert(typeof off === 'number');

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
  assert(typeof s === 'string');
  assert(typeof n === 'number');

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
  assert(typeof a === 'string');
  assert(typeof b === 'string');

  if (a.length !== b.length)
    return false;

  for (let i = a.length - 1; i >= 0; i--) {
    let ai = a.charCodeAt(i);
    let bi = b.charCodeAt(i);

    if (ai >= 0x41 && ai <= 0x5a)
      ai |= 0x20;

    if (bi >= 0x41 && bi <= 0x5a)
      bi |= 0x20;

    if (ai !== bi)
      return false;
  }

  return true;
};

util.isName = function isName(s) {
  assert(typeof s === 'string');

  try {
    sizeName(util.fqdn(s), null, false);
    return true;
  } catch (e) {
    return false;
  }
};

util.isFQDN = function isFQDN(s) {
  assert(typeof s === 'string');

  if (s.length === 0)
    return false;

  return s[s.length - 1] === '.';
};

util.fqdn = function fqdn(s) {
  assert(typeof s === 'string');

  if (util.isFQDN(s))
    return s;

  return s + '.';
};

util.isSubdomain = function isSubdomain(parent, child) {
  return util.compareName(parent, child) === util.countLabels(parent);
};

util.addOrigin = function addOrigin(s, origin) {
  assert(typeof s === 'string');
  assert(typeof origin === 'string');

  if (util.isFQDN(s))
    return s;

  if (origin.length === 0)
    return false;

  if (s === '@' || s.length === 0)
    return origin;

  if (origin === '.')
    return util.fqdn(s);

  return `${s}.${origin}`;
};

util.trimFQDN = function trimFQDN(s) {
  assert(typeof s === 'string');

  if (s.length === 0)
    return s;

  if (s[s.length - 1] === '.')
    s = s.slice(0, -1);

  return s;
};

util.trimDomainName = function trimDomainName(s, origin) {
  assert(typeof s === 'string');
  assert(typeof origin === 'string');

  if (s.length === 0)
    return '@';

  if (origin === '.')
    return util.trimRoot(s);

  const original = s;

  s = util.fqdn(s);
  origin = util.fqdn(origin);

  if (!util.isSubdomain(origin, s))
    return original;

  const slabels = util.split(s);
  const olabels = util.split(origin);
  const m = util.compareName(s, origin);

  if (olabels.length === m) {
    if (olabels.length === slabels.length)
      return '@';

    if (s[0] === '.' && slabels.length === olabels.length + 1)
      return '@';
  }

  return s.substring(0, slabels[slabels.length - m] - 1);
};

util.label = function label(s, labels, index) {
  if (typeof labels === 'number') {
    index = labels;
    labels = util.split(s);
  }

  assert(typeof s === 'string');
  assert(Array.isArray(labels));
  assert(typeof index === 'number');

  if (index < 0)
    index += labels.length;

  if (index >= labels.length)
    return '';

  const start = labels[index];

  if (index + 1 === labels.length) {
    if (util.isFQDN(s))
      return s.slice(start, -1);
    return s.substring(start);
  }

  const end = labels[index + 1];

  return s.substring(start, end - 1);
};

util.from = function from(s, labels, index) {
  if (typeof labels === 'number') {
    index = labels;
    labels = util.split(s);
  }

  assert(typeof s === 'string');
  assert(Array.isArray(labels));
  assert(typeof index === 'number');

  if (index < 0)
    index += labels.length;

  if (index >= labels.length)
    return '';

  return s.substring(labels[index]);
};

util.to = function to(s, labels, index) {
  if (typeof labels === 'number') {
    index = labels;
    labels = util.split(s);
  }

  assert(typeof s === 'string');
  assert(Array.isArray(labels));
  assert(typeof index === 'number');

  if (index < 0)
    index += labels.length;

  if (index >= labels.length)
    return '';

  return s.substring(0, labels[index]);
};

util.startsWith = function startsWith(s, pre) {
  assert(typeof s === 'string');
  assert(typeof pre === 'string');

  if (s.startsWith)
    return s.startsWith(pre);

  if (pre.length === 0)
    return true;

  if (s.length === 0)
    return false;

  if (pre.length > s.length)
    return false;

  if (pre.length === 1)
    return s[0] === pre;

  return s.substring(0, pre.length) === pre;
};

util.endsWith = function endsWith(s, suf) {
  assert(typeof s === 'string');
  assert(typeof suf === 'string');

  if (s.endsWith)
    return s.endsWith(suf);

  if (suf.length === 0)
    return true;

  if (s.length === 0)
    return false;

  if (suf.length > s.length)
    return false;

  if (suf.length === 1)
    return s[s.length - 1] === suf;

  return s.slice(-suf.length) === suf;
};

util.trimPrefix = function trimPrefix(s, pre) {
  if (util.startsWith(s, pre))
    return s.slice(pre.length);
  return s;
};

util.trimSuffix = function trimSuffix(s, suf) {
  if (util.endsWith(s, suf))
    return s.slice(0, -suf.length);
  return s;
};

util.isRRSet = function isRRSet(rrset) {
  assert(Array.isArray(rrset));

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
        || !util.equal(rr.name, name)) {
      return false;
    }
  }

  return true;
};

util.filterSet = function filterSet(records, ...types) {
  assert(Array.isArray(records));

  const set = new Set(types);
  const out = [];

  for (const rr of records) {
    if (!set.has(rr.type))
      out.push(rr);
  }

  return out;
};

util.extractSet = function extractSet(records, name, ...types) {
  assert(Array.isArray(records));
  assert(typeof name === 'string');

  const set = new Set(types);
  const out = [];

  for (const rr of records) {
    if (set.has(rr.type)) {
      if (name !== '' && !util.equal(rr.name, name))
        continue;
      out.push(rr);
    }
  }

  return out;
};

util.hasType = function hasType(records, type) {
  assert(Array.isArray(records));
  assert(typeof type === 'number');

  for (const rr of records) {
    if (rr.type === type)
      return true;
  }

  return false;
};

util.hasAll = function hasAll(records, type) {
  assert(Array.isArray(records));
  assert(typeof type === 'number');

  for (const rr of records) {
    if (rr.type !== type)
      return false;
  }

  return true;
};

util.random = function random(n) {
  assert(typeof n === 'number');
  return Math.floor(Math.random() * n);
};

util.randomItem = function randomItem(items) {
  assert(Array.isArray(items));
  return items[util.random(items.length)];
};

util.now = function now() {
  return Math.floor(Date.now() / 1000);
};

util.digDate = function digDate(time) {
  const d = time != null ? new Date(time * 1000) : new Date();
  const str = d.toString();
  const parts = str.split(' ');
  const [day, month, date, year, ts, , tz] = parts;
  const z = tz.slice(1, -1);
  return `${day} ${month} ${date} ${ts} ${z} ${year}`;
};

util.parseInteger = function parseInteger(str, max, size) {
  assert(typeof str === 'string');

  let word = 0;

  if (str.length > size)
    throw new Error('Invalid integer.');

  for (let i = 0; i < str.length; i++) {
    const ch = str.charCodeAt(i) - 0x30;

    if (ch < 0 || ch > 9)
      throw new Error('Invalid integer.');

    word *= 10;
    word += ch;

    if (word > max)
      throw new Error('Invalid integer.');
  }

  return word;
};

util.parseU8 = function parseU8(str) {
  return util.parseInteger(str, 0xff, 3);
};

util.parseU16 = function parseU16(str) {
  return util.parseInteger(str, 0xffff, 5);
};

util.parseU32 = function parseU32(str) {
  return util.parseInteger(str, 0xffffffff, 10);
};

util.parseU48 = function parseU48(str) {
  return util.parseInteger(str, 0xffffffffffff, 15);
};

util.parseU64 = function parseU64(str) {
  assert(typeof str === 'string');

  if (str.length > 20)
    throw new Error('Invalid integer.');

  let hi = 0;
  let lo = 0;

  for (let i = 0; i < str.length; i++) {
    const ch = str.charCodeAt(i) - 0x30;

    if (ch < 0 || ch > 9)
      throw new Error('Invalid integer.');

    lo *= 10;
    lo += ch;

    hi *= 10;

    if (lo > 0xffffffff) {
      const m = lo % 0x100000000;
      hi += (lo - m) / 0x100000000;
      lo = m;
    }

    if (hi > 0xffffffff)
      throw new Error('Invalid integer.');
  }

  return [hi, lo];
};

util.serializeU64 = function serializeU64(hi, lo) {
  assert((hi >>> 0) === hi);
  assert((lo >>> 0) === lo);

  let str = '';

  do {
    const mhi = hi % 10;
    hi -= mhi;
    hi /= 10;
    lo += mhi * 0x100000000;

    const mlo = lo % 10;
    lo -= mlo;
    lo /= 10;

    const ch = mlo + 0x30;

    str = String.fromCharCode(ch) + str;
  } while (lo > 0 || hi > 0);

  return str;
};

util.dir = function dir(obj, inspect = true) {
  console.dir(obj, {
    depth: 20,
    colors: true,
    customInspect: inspect
  });
};

util.isIP = function isIP(host) {
  try {
    IP.toBuffer(host);
    return true;
  } catch (e) {
    return false;
  }
};

util.id = function id() {
  return (Math.random() * 0x10000) >>> 0;
};
