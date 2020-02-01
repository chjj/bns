/*!
 * util.js - utils for bns
 * Copyright (c) 2018, Christopher Jeffrey (MIT License).
 * https://github.com/chjj/bns
 *
 * Parts of this software are based on miekg/dns and golang/go:
 *   https://github.com/miekg/dns/blob/master/labels.go
 *   https://github.com/miekg/dns/blob/master/dnsutil/util.go
 */

/* eslint spaced-comment: 0 */

'use strict';

const assert = require('bsert');
const IP = require('binet');
const rng = require('bcrypto/lib/random');
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

  if (util.isFQDN(s))
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
      for (let i = 1; i < idx.length; i++) {
        const end = idx[i];
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

  if (s.length === 0)
    return [0, true];

  let i = 0;

  for (i = off; i < s.length - 1; i++) {
    if (s.charCodeAt(i) !== 0x2e) /*.*/
      continue;

    let j = i - 1;

    while (j >= 0 && s.charCodeAt(j) === 0x5c) /*\*/
      j -= 1;

    if ((j - i) % 2 === 0)
      continue;

    return [i + 1, false];
  }

  return [i + 1, true];
};

util.prevLabel = function prevLabel(s, n) {
  assert(typeof s === 'string');
  assert(typeof n === 'number');

  if (s.length === 0)
    return [0, true];

  if (n === 0)
    return [s.length, false];

  let i = s.length - 1;

  if (s.charCodeAt(i) === 0x2e) /*.*/
    i -= 1;

  for (; i >= 0 && n > 0; i--) {
    if (s.charCodeAt(i) !== 0x2e) /*.*/
      continue;

    let j = i - 1;

    while (j >= 0 && s.charCodeAt(j) === 0x5c) /*\*/
      j -= 1;

    if ((j - i) % 2 === 0)
      continue;

    n -= 1;

    if (n === 0)
      return [i + 1, false];
  }

  return [0, n > 1];
};

util.equal = function equal(a, b) {
  assert(typeof a === 'string');
  assert(typeof b === 'string');

  if (a.length !== b.length)
    return false;

  for (let i = a.length - 1; i >= 0; i--) {
    let x = a.charCodeAt(i);
    let y = b.charCodeAt(i);

    if (x >= 0x41 && x <= 0x5a)
      x |= 0x20;

    if (y >= 0x41 && y <= 0x5a)
      y |= 0x20;

    if (x !== y)
      return false;
  }

  return true;
};

util.compare = function compare(a, b) {
  assert(typeof a === 'string');
  assert(typeof b === 'string');

  const len = Math.min(a.length, b.length);

  for (let i = 0; i < len; i++) {
    let x = a.charCodeAt(i);
    let y = b.charCodeAt(i);

    if (x >= 0x41 && x <= 0x5a)
      x |= 0x20;

    if (y >= 0x41 && y <= 0x5a)
      y |= 0x20;

    if (x < y)
      return -1;

    if (x > y)
      return 1;
  }

  if (a.length < b.length)
    return -1;

  if (a.length > b.length)
    return 1;

  return 0;
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

  const i = s.length - 1;

  if (s.charCodeAt(i) !== 0x2e) /*.*/
    return false;

  let j = i - 1;

  while (j >= 0 && s.charCodeAt(j) === 0x5c) /*\*/
    j -= 1;

  return (j - i) % 2 !== 0;
};

util.fqdn = function fqdn(s) {
  if (util.isFQDN(s))
    return s;

  return s + '.';
};

util.trimFQDN = function trimFQDN(s) {
  if (!util.isFQDN(s))
    return s;

  return s.slice(0, -1);
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
    return s;

  if (s === '@' || s.length === 0)
    return origin;

  if (origin === '.')
    return util.fqdn(s);

  return `${s}.${origin}`;
};

util.trimDomainName = function trimDomainName(s, origin) {
  assert(typeof s === 'string');
  assert(typeof origin === 'string');

  if (s.length === 0)
    return '@';

  if (origin === '.')
    return util.trimFQDN(s);

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
  return rng.randomRange(0, n);
};

util.randomItem = function randomItem(items) {
  assert(Array.isArray(items));
  return items[util.random(items.length)];
};

util.timeOffset = 0;

util.now = function now() {
  return Math.floor(Date.now() / 1000) + util.timeOffset;
};

util.fakeTime = function fakeTime(time) {
  if (time == null)
    time = 0;

  if (typeof time === 'string')
    time = Math.floor(Date.parse(time) / 1000);

  assert(Number.isSafeInteger(time));
  assert(time >= 0);

  if (time === 0) {
    util.timeOffset = 0;
    return;
  }

  const now = Math.floor(Date.now() / 1000);

  util.timeOffset = time - now;
};

util.digDate = function digDate(time) {
  if (time == null)
    time = util.now();

  assert(Number.isSafeInteger(time));
  assert(time >= 0);

  const date = new Date(time * 1000);

  // We need to replicate something like:
  //   Tue Jun 12 21:27:00 PDT 2018
  // We use only ECMA-262 enforced methods
  // for this for compatibility purposes.

  // Format: Wed Jun 28 1993
  const ds = date.toDateString();

  // Format: 14:39:07 GMT-0700 (PDT)
  const ts = date.toTimeString();

  const dp = ds.split(' ');
  const tp = ts.split(' ');

  const [n, m, d, y] = dp;
  const [t] = tp;

  let z = '';

  // Timezone parsing.
  if (tp.length === 3) {
    // The timezone is in short form, e.g.
    //   14:39:07 GMT-0700 (PDT)
    z = tp[2];

    if (z[0] === '(')
      z = z.slice(1, -1);
  } else if (tp.length > 3) {
    // We have something like:
    //   22:03:24 GMT-0700 (Pacific Daylight Time)
    // Newer versions of v8 tend to do this.
    z = '';

    // Abbreviate.
    for (let i = 2; i < tp.length; i++) {
      const p = tp[i];

      if (i === 2 && p[0] === '(')
        z += p[1];
      else
        z += p[0];
    }
  } else {
    // Fallback to GMT+offset, e.g.
    //   GMT-0700
    z = tp[1];
  }

  return `${n} ${m} ${d} ${t} ${z} ${y}`;
};

util.parseInteger = function parseInteger(str, max, size) {
  assert(typeof str === 'string');

  let word = 0;

  if (str.length === 0 || str.length > size)
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

  if (str.length === 0 || str.length > 20)
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
  return IP.test(host) !== 0;
};

util.id = function id() {
  return rng.randomInt() & 0xffff;
};

util.cookie = function cookie() {
  return rng.randomBytes(8);
};

util.sortRandom = function sortRandom(items) {
  assert(Array.isArray(items));

  if (items.length <= 1)
    return items;

  return items.slice().sort(cmpRandom);
};

util.ensureLF = function ensureLF(str) {
  assert(typeof str === 'string');

  str = str.replace(/\r\n/g, '\n');
  str = str.replace(/\r/g, '\n');

  return str;
};

util.ensureSP = function ensureSP(str) {
  assert(typeof str === 'string');
  return str.replace(/[ \t\v]/g, ' ');
};

util.splitLF = function splitLF(str, limit) {
  assert(typeof str === 'string');
  if (limit === null)
    limit = undefined;
  return str.trim().split(/\n+/, limit);
};

util.splitSP = function splitSP(str, limit) {
  assert(typeof str === 'string');
  if (limit === null)
    limit = undefined;
  return str.trim().split(/[ \t\v]+/, limit);
};

util.stripBOM = function stripBOM(str) {
  assert(typeof str === 'string');

  if (str.length === 0)
    return str;

  if (str.charCodeAt(0) !== 0xfeff)
    return str;

  return str.substring(1);
};

util.stripSP = function stripSP(str) {
  assert(typeof str === 'string');
  return str.replace(/[ \t\v]+/g, '');
};

util.stripLF = function stripLF(str) {
  assert(typeof str === 'string');
  return str.replace(/\n+/g, '');
};

util.splitColon = function splitColon(str) {
  assert(typeof str === 'string');

  const index = str.indexOf(':');

  if (index === -1)
    return [str.toLowerCase(), ''];

  const left = str.substring(0, index).trim();
  const right = str.substring(index + 1).trim();

  return [left, right];
};

util.splitLines = function splitLines(str, escaped, limit) {
  assert(typeof str === 'string');

  str = util.stripBOM(str);
  str = util.ensureLF(str);
  str = util.ensureSP(str);

  if (escaped)
    str = str.replace(/\\\n/g, '');

  const lines = util.splitLF(str, limit);
  const out = [];

  for (const chunk of lines) {
    const line = chunk.trim();

    if (line.length === 0)
      continue;

    out.push(line);
  }

  return out;
};

util.isHex = function isHex(str) {
  assert(typeof str === 'string');

  if (str.length & 1)
    return false;

  return /^[A-Fa-f0-9]+$/.test(str);
};

util.parseHex = function parseHex(str) {
  assert(typeof str === 'string');

  if (str.length & 1)
    throw new Error('Invalid hex string.');

  const data = Buffer.from(str, 'hex');

  if (data.length !== (str.length >>> 1))
    throw new Error('Invalid hex string.');

  return data;
};

util.isB64 = function isB64(str) {
  assert(typeof str === 'string');
  return /^[A-Za-z0-9+\/=]+$/.test(str);
};

util.parseB64 = function parseB64(str) {
  assert(typeof str === 'string');

  const data = Buffer.from(str, 'base64');

  if (str.length > size64(data.length))
    throw new Error('Invalid base64 string.');

  return data;
};

util.padRight = function padRight(data, size) {
  assert(Buffer.isBuffer(data));
  assert((size >>> 0) === size);

  if (data.length < size) {
    const buf = Buffer.allocUnsafe(size);
    data.copy(buf, 0);
    buf.fill(0x00, data.length, size);
    return buf;
  }

  if (data.length > size)
    return data.slice(0, size);

  return data;
};

util.pad = function pad(num, len) {
  assert((num >>> 0) === num);
  assert((len >>> 0) === len);

  let str = num.toString(10);

  while (str.length < len)
    str = '0' + str;

  return str;
};

util.parseTime = function parseTime(s) {
  assert(typeof s === 'string');
  assert(s.length === 14);

  const y = unpad(s, 0, 4);
  const m = unpad(s, 4, 6);
  const d = unpad(s, 6, 8);
  const hr = unpad(s, 8, 10);
  const mn = unpad(s, 10, 12);
  const sc = unpad(s, 12, 14);
  const da = new Date(0);

  da.setUTCFullYear(y);
  da.setUTCMonth(m - 1);
  da.setUTCDate(d);
  da.setUTCHours(hr);
  da.setUTCMinutes(mn);
  da.setUTCSeconds(sc);
  da.setUTCMilliseconds(0);

  const ms = da.getTime();

  if (!Number.isSafeInteger(ms))
    throw new RangeError('Invalid time value.');

  assert(ms % 1000 === 0);

  return ms / 1000;
};

util.serializeTime = function serializeTime(t) {
  assert(Number.isSafeInteger(t));
  assert(Number.isSafeInteger(t * 1000));

  const da = new Date(t * 1000);
  const ms = da.getTime();

  if (!Number.isSafeInteger(ms))
    throw new RangeError('Invalid time value.');

  const y = util.pad(da.getUTCFullYear(), 4);
  const m = util.pad(da.getUTCMonth() + 1, 2);
  const d = util.pad(da.getUTCDate(), 2);
  const hr = util.pad(da.getUTCHours(), 2);
  const mn = util.pad(da.getUTCMinutes(), 2);
  const sc = util.pad(da.getUTCSeconds(), 2);

  return `${y}${m}${d}${hr}${mn}${sc}`;
};

util.serial = function serial(t) {
  assert(Number.isSafeInteger(t));
  assert(Number.isSafeInteger(t * 1000));

  const date = new Date(t * 1000);
  const ms = date.getTime();

  if (!Number.isSafeInteger(ms))
    throw new RangeError('Invalid time value.');

  const y = date.getUTCFullYear() * 1e6;
  const m = (date.getUTCMonth() + 1) * 1e4;
  const d = date.getUTCDate() * 1e2;
  const h = date.getUTCHours();

  return y + m + d + h;
};

/*
 * Helpers
 */

function cmpRandom(a, b) {
  return -(rng.randomInt() & 1) | 1;
}

function unpad(str, start, end) {
  const num = str.substring(start, end);
  return util.parseU16(num);
}

function size64(size) {
  const expect = ((4 * size / 3) + 3) & ~3;
  return expect >>> 0;
}
