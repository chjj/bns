/*!
 * punycode.js - punycode for bns
 * Copyright (c) 2019, Christopher Jeffrey (MIT License).
 * https://github.com/chjj/bns
 *
 * Parts of this software are based on bestiejs/punycode.js:
 *   Copyright (c) 2011-2019, Mathias Bynens (MIT License)
 *   https://github.com/bestiejs/punycode.js
 *   https://mths.be/punycode
 *
 * Resources:
 *   https://www.ietf.org/rfc/rfc3492.txt
 *   https://en.wikipedia.org/wiki/Punycode
 *   https://github.com/bestiejs/punycode.js/blob/master/punycode.js
 */

'use strict';

const assert = require('bsert');

/*
 * Constants
 */

const MAX_INT = 2147483647;
const BASE = 36;
const T_MIN = 1;
const T_MAX = 26;
const SKEW = 38;
const DAMP = 700;
const INITIAL_BIAS = 72;
const INITIAL_N = 128;
const BASE_MINUS_T_MIN = BASE - T_MIN;
const DELIMITER = '-';
const PUNYCODE_RX = /^xn--/;
const NONASCII_RX = /[^\0-\x7e]/;
const SEPARATORS_RX = /[\x2e\u3002\uff0e\uff61]/g;

/*
 * Errors
 */

const errors = {
  OVERFLOW: 'Overflow: input needs wider integers to process.',
  NOT_BASIC: 'Illegal input >= 0x80 (not a basic code point).',
  INVALID_INPUT: 'Invalid input.'
};

/*
 * API
 */

function encodeRaw(str) {
  assert(typeof str === 'string');

  const codes = ucs2decode(str);

  let n = INITIAL_N;
  let delta = 0;
  let bias = INITIAL_BIAS;
  let len = 0;
  let output = '';

  for (let i = 0; i < codes.length; i++) {
    const ch = codes[i];

    if (ch >= 0x80)
      continue;

    output += String.fromCharCode(ch);
    len += 1;
  }

  let handled = len;

  if (len > 0)
    output += DELIMITER;

  while (handled < codes.length) {
    let m = MAX_INT;

    for (let i = 0; i < codes.length; i++) {
      const ch = codes[i];

      if (ch >= n && ch < m)
        m = ch;
    }

    const hpo = handled + 1;

    if (m - n > Math.floor((MAX_INT - delta) / hpo))
      throw new RangeError(errors.OVERFLOW);

    delta += (m - n) * hpo;
    n = m;

    for (let i = 0; i < codes.length; i++) {
      const ch = codes[i];

      if (ch < n) {
        delta += 1;
        if (delta > MAX_INT)
          throw new RangeError(errors.OVERFLOW);
      }

      if (ch !== n)
        continue;

      let q = delta;
      let k = BASE;

      for (;;) {
        let t = T_MIN;

        if (k > bias) {
          if (k >= bias + T_MAX)
            t = T_MAX;
          else
            t = k - bias;
        }

        if (q < t)
          break;

        const qmt = q - t;
        const bmt = BASE - t;

        output += basic(t + qmt % bmt, 0);

        q = Math.floor(qmt / bmt);
        k += BASE;
      }

      output += basic(q, 0);

      bias = adapt(delta, hpo, handled === len);
      delta = 0;
      handled += 1;
    }

    delta += 1;
    n += 1;
  }

  return output;
}

function decodeRaw(str) {
  assert(typeof str === 'string');

  let delim = str.lastIndexOf(DELIMITER);

  if (delim < 0)
    delim = 0;

  const codes = [];

  for (let i = 0; i < delim; i++) {
    const ch = str.charCodeAt(i);

    if (ch >= 0x80)
      throw new RangeError(errors.NOT_BASIC);

    codes.push(ch);
  }

  let i = 0;
  let n = INITIAL_N;
  let bias = INITIAL_BIAS;
  let index = delim > 0 ? delim + 1 : 0;

  while (index < str.length) {
    const j = i;

    let w = 1;
    let k = BASE;

    for (;;) {
      if (index >= str.length)
        throw new RangeError(errors.INVALID_INPUT);

      const ch = digit(str, index);

      index += 1;

      if (ch >= BASE || ch > Math.floor((MAX_INT - i) / w))
        throw new RangeError(errors.OVERFLOW);

      i += ch * w;

      let t = T_MIN;

      if (k > bias) {
        if (k >= bias + T_MAX)
          t = T_MAX;
        else
          t = k - bias;
      }

      if (ch < t)
        break;

      const bmt = BASE - t;

      if (w > Math.floor(MAX_INT / bmt))
        throw new RangeError(errors.OVERFLOW);

      w *= bmt;
      k += BASE;
    }

    const out = codes.length + 1;

    bias = adapt(i - j, out, j === 0);

    if (Math.floor(i / out) > MAX_INT - n)
      throw new RangeError(errors.OVERFLOW);

    n += Math.floor(i / out);
    i %= out;

    codes.splice(i, 0, n);
    i += 1;
  }

  return String.fromCodePoint(...codes);
}

function encode(str) {
  assert(typeof str === 'string');

  return map(str, (label) => {
    return NONASCII_RX.test(label)
      ? 'xn--' + encodeRaw(label)
      : label;
  });
}

function decode(str) {
  assert(typeof str === 'string');

  return map(str, (label) => {
    return PUNYCODE_RX.test(label)
      ? decodeRaw(label.substring(4).toLowerCase())
      : label;
  });
}

/*
 * Helpers
 */

function ucs2encode(codes) {
  assert(Array.isArray(codes));

  for (const code of codes)
    assert((code >>> 0) === code);

  return String.fromCodePoint(...codes);
}

function ucs2decode(str) {
  assert(typeof str === 'string');

  const codes = [];

  for (let i = 0; i < str.length; i++) {
    const ch = str.charCodeAt(i);

    if (ch >= 0xd800 && ch <= 0xdbff && i + 1 < str.length) {
      const x = str.charCodeAt(i + 1);

      if ((x & 0xfc00) === 0xdc00) {
        codes.push(((ch & 0x3ff) << 10) + (x & 0x3ff) + 0x10000);
        i += 1;
        continue;
      }
    }

    codes.push(ch);
  }

  return codes;
}

function digit(str, index) {
  assert(typeof str === 'string');
  assert((index >>> 0) === index);
  assert(index < str.length);

  const code = str.charCodeAt(index);

  if (code - 0x30 < 0x0a)
    return code - 0x16;

  if (code - 0x41 < 0x1a)
    return code - 0x41;

  if (code - 0x61 < 0x1a)
    return code - 0x61;

  return BASE;
}

function basic(ch, flag) {
  assert((ch >>> 0) === ch);
  assert((flag >>> 0) === flag);

  ch += 22 + 75 * (ch < 26);
  ch -= ((flag !== 0) << 5);

  return String.fromCharCode(ch);
}

function adapt(delta, points, first) {
  assert((delta >>> 0) === delta);
  assert((points >>> 0) === points);
  assert(typeof first === 'boolean');

  let k = 0;

  delta = first ? Math.floor(delta / DAMP) : delta >> 1;
  delta += Math.floor(delta / points);

  for (; delta > BASE_MINUS_T_MIN * T_MAX >> 1; k += BASE)
    delta = Math.floor(delta / BASE_MINUS_T_MIN);

  return Math.floor(k + (BASE_MINUS_T_MIN + 1) * delta / (delta + SKEW));
}

function map(str, fn) {
  assert(typeof str === 'string');
  assert(typeof fn === 'function');

  const index = str.indexOf('@');

  let result = '';

  if (index !== -1) {
    result = str.substring(0, index + 1);
    str = str.substring(index + 1);
  }

  str = str.replace(SEPARATORS_RX, '.');

  const labels = str.split('.');
  const encoded = [];

  for (const label of labels)
    encoded.push(fn(label));

  return result + encoded.join('.');
}

/*
 * Expose
 */

exports._ucs2encode = ucs2encode;
exports._ucs2decode = ucs2decode;
exports.encodeRaw = encodeRaw;
exports.decodeRaw = decodeRaw;
exports.encode = encode;
exports.decode = decode;
