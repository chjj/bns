/*!
 * encoding.js - encoding for bns
 * Copyright (c) 2018, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bns
 *
 * Parts of this software are based on miekg/dns and golang/go:
 *   https://github.com/miekg/dns/blob/master/msg.go
 *   https://github.com/miekg/dns/blob/master/types.go
 *   https://github.com/golang/go/blob/master/src/net/dnsmsg.go
 */

/* eslint spaced-comment: 0 */

'use strict';

const assert = require('assert');
const IP = require('binet');
const {EncodingError} = require('bufio');
const {MAX_NAME_SIZE, MAX_LABEL_SIZE} = require('./constants');

const ASCII = [
  ' ', ' ', ' ', ' ', ' ', ' ', ' ', ' ',
  ' ', ' ', ' ', ' ', ' ', ' ', ' ', ' ',
  ' ', ' ', ' ', ' ', ' ', ' ', ' ', ' ',
  ' ', ' ', ' ', ' ', ' ', ' ', ' ', ' ',
  ' ', '!', '"', '#', '$', '%', '&', '\'',
  '(', ')', '*', '+', ',', '-', '.', '/',
  '0', '1', '2', '3', '4', '5', '6', '7',
  '8', '9', ':', ';', '<', '=', '>', '?',
  '@', 'A', 'B', 'C', 'D', 'E', 'F', 'G',
  'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O',
  'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W',
  'X', 'Y', 'Z', '[', '\\', ']', '^', '_',
  '`', 'a', 'b', 'c', 'd', 'e', 'f', 'g',
  'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o',
  'p', 'q', 'r', 's', 't', 'u', 'v', 'w',
  'x', 'y', 'z', '{', '|', '}', '~', ' '
];

const HEX = [
  '0', '1', '2', '3', '4', '5', '6', '7',
  '8', '9', 'a', 'b', 'c', 'd', 'e', 'f'
];

const NAME_BUFFER = Buffer.allocUnsafe(MAX_NAME_SIZE * 4);

const encoding = exports;

encoding.sizeName = function sizeName(name, map, cmp) {
  const [off] = encoding.writeName(null, name, 0, map, cmp);
  return off;
};

encoding.writeName = function writeName(data, name, off, map, cmp) {
  if (data == null)
    data = null;

  if (map == null)
    map = null;

  if (cmp == null)
    cmp = false;

  assert(data === null || Buffer.isBuffer(data));
  assert(typeof name === 'string');
  assert((off >>> 0) === off);
  assert(map === null || (map instanceof Map));
  assert(typeof cmp === 'boolean');

  let nl = name.length;

  if (nl === 0 || name[nl - 1] !== '.')
    throw new EncodingError(0, 'No dot');

  if (nl > MAX_NAME_SIZE * 4)
    throw new EncodingError(0, 'Name too large');

  const n = NAME_BUFFER;

  if (n.write(name, 'ascii') !== nl)
    throw new EncodingError(0, 'Bad ascii string');

  let pos = -1;
  let ptr = -1;
  let begin = 0;
  let escaped = false;
  let fresh = true;
  let labels = 0;

  for (let i = 0; i < nl; i++) {
    if (n[i] === 0x5c /*\\*/) {
      for (let j = i; j < nl - 1; j++)
        n[j] = n[j + 1];

      nl -= 1;

      if (i + 2 < nl
          && isDigit(n[i + 0])
          && isDigit(n[i + 1])
          && isDigit(n[i + 2])) {
        n[i] = toByte(n, i);
        for (let j = i + 1; j < nl - 2; j++)
          n[j] = n[j + 2];
        nl -= 2;
      }

      escaped = n[i] === 0x2e;
      fresh = false;

      continue;
    }

    if (n[i] === 0x2e /*.*/) {
      if (i > 0 && n[i - 1] === 0x2e /*.*/ && !escaped)
        throw new EncodingError(off, 'Multiple dots');

      const size = i - begin;

      if (size > MAX_LABEL_SIZE)
        throw new EncodingError(off, 'Max label size exceeded');

      if (data) {
        if (off + 1 + size > data.length)
          throw new EncodingError(off, 'EOF');
        data[off] = size;
      }

      const offset = off;

      off += 1;

      if (data)
        assert(n.copy(data, off, begin, i) === size);

      off += size;

      if (cmp && !fresh) {
        name = n.toString('ascii', 0, nl);
        fresh = true;
      }

      if (map) {
        const s = name.substring(begin);
        if (s !== '.') {
          const p = map.get(s);
          if (p == null) {
            if (offset < (2 << 13))
              map.set(s, offset);
          } else {
            if (cmp && ptr === -1) {
              ptr = p;
              pos = offset;
              break;
            }
          }
        }
      }

      labels += 1;
      begin = i + 1;
    }

    escaped = false;
  }

  if (nl > MAX_NAME_SIZE)
    throw new EncodingError(off, 'Max name size exceeded');

  if (nl === 1 && n[0] === 0x2e /*.*/)
    return [off, labels];

  if (ptr !== -1) {
    if (data)
      data.writeUInt16BE(pos, ptr ^ 0xc000, true);
    off = pos + 2;
    return [off, labels];
  }

  if (data) {
    if (off >= data.length)
      throw new EncodingError(off, 'EOF');
    data[off] = 0;
  }

  off += 1;

  return [off, labels];
};

encoding.readName = function readName(data, off) {
  assert(Buffer.isBuffer(data));
  assert((off >>> 0) === off);

  let name = '';
  let res = 0;
  let max = MAX_NAME_SIZE;
  let ptr = 0;

  for (;;) {
    if (off >= data.length)
      throw new EncodingError(off, 'EOF');

    const c = data[off];

    off += 1;

    if (c === 0x00)
      break;

    switch (c & 0xc0) {
      case 0x00: {
        if (c > MAX_LABEL_SIZE)
          throw new EncodingError(off, 'Max label size exceeded');

        if (off + c > data.length)
          throw new EncodingError(off, 'EOF');

        if (name.length + c + 1 > max)
          throw new EncodingError(off, 'Max name length exceeded');

        for (let j = off; j < off + c; j++) {
          const b = data[j];

          switch (b) {
            case 0x2e /*.*/:
            case 0x28 /*(*/:
            case 0x29 /*)*/:
            case 0x3b /*;*/:
            case 0x20 /* */:
            case 0x40 /*@*/:
            case 0x22 /*"*/:
            case 0x5c /*\\*/: {
              name += '\\' + ASCII[b];
              max += 1;
              break;
            }
            default: {
              if (b < 0x20 || b > 0x7e) {
                name += '\\' + toDDD(b);
                max += 3;
              } else {
                name += ASCII[b];
              }
              break;
            }
          }
        }

        name += '.';
        off += c;

        break;
      }

      case 0xc0: {
        if (off >= data.length)
          throw new EncodingError(off, 'EOF');

        const c1 = data[off];

        off += 1;

        if (ptr === 0)
          res = off;

        ptr += 1;

        if (ptr > 10)
          throw new EncodingError(off, 'Too many pointers');

        off = ((c ^ 0xc0) << 8) | c1;

        break;
      }

      default: {
        throw new EncodingError(off, 'Invalid byte');
      }
    }
  }

  if (ptr === 0)
    res = off;

  if (name.length === 0)
    name = '.';

  assert(name.length <= max);

  return [res, name];
};

encoding.writeNameBW = function writeNameBW(bw, name, map, cmp) {
  const {data, offset} = bw;
  const [off, labels] = encoding.writeName(data, name, offset, map, cmp);
  bw.offset = off;
  return labels;
};

encoding.readNameBR = function readNameBR(br) {
  const [off, name] = encoding.readName(br.data, br.offset);
  br.offset = off;
  return name;
};

encoding.packName = function packName(name) {
  const size = encoding.sizeName(name, null, false);
  const data = Buffer.allocUnsafe(size);
  encoding.writeName(data, name, 0, null, false);
  return data;
};

encoding.unpackName = function unpackName(data) {
  const [, name] = encoding.readName(data, 0);
  return name;
};

encoding.reverse = function reverse(addr) {
  const ip = IP.toBuffer(addr);

  if (IP.isIPv4(ip)) {
    const name = `${ip[15]}.${ip[14]}.${ip[13]}.${ip[12]}.`;
    return `${name}in-addr.arpa.`;
  }

  let name = '';

  for (let i = ip.length - 1; i >= 0; i--) {
    const ch = ip[i];
    name += HEX[ch & 0x0f];
    name += '.';
    name += HEX[ch >>> 4];
    name += '.';
  }

  return `${name}ip6.arpa.`;
};

encoding.fromBitmap = function fromBitmap(map) {
  assert(Buffer.isBuffer(map));
  assert(map.length <= 34 * 256);

  const types = [];

  let i = 0;

  while (i < map.length) {
    if (i + 2 > map.length)
      return types;

    assert(i + 2 <= map.length);

    const hi = map[i++];
    const len = map[i++];
    const size = len << 3;

    if (len === 0 || len > 32)
      return types;

    if (i + len > map.length)
      return types;

    assert(len > 0 && len <= 32);
    assert(i + len <= map.length);

    for (let lo = 0; lo < size; lo++) {
      const oct = lo >>> 3;
      const bit = lo & 7;
      const ch = map[i + oct];
      const mask = 1 << (7 - bit);

      if (ch & mask) {
        const type = (hi << 8) | lo;
        types.push(type);
      }
    }
  }

  return types;
};

encoding.toBitmap = function toBitmap(types) {
  assert(Array.isArray(types));

  if (types.length === 0)
    return Buffer.allocUnsafe(0);

  assert(types.length <= 8192);

  types = types.slice().sort(compare);

  const max = types[types.length - 1];
  const wins = (max >>> 8) + 1;
  const size = wins * 34;
  const map = Buffer.alloc(size, 0x00);

  for (let i = 0; i < types.length; i++) {
    const type = types[i];

    assert((type & 0xffff) === type);

    if (i > 0 && types[i - 1] === type)
      continue;

    const hi = type >>> 8;
    const lo = type & 0xff;
    const oct = (hi * 34) + (lo >>> 3);
    const bit = lo & 7;

    map[oct] |= 1 << (7 - bit);
  }

  let off = 0;

  for (let win = 0; win < wins; win++) {
    const pos = (win * 34) + 2;

    let i = 31;

    for (; i >= 0; i--) {
      if (map[pos + i] !== 0)
        break;
    }

    const len = i + 1;

    if (len === 0)
      continue;

    map[off++] = win;
    map[off++] = len;

    off += map.copy(map, off, pos, pos + len);
  }

  return map.slice(0, off);
};

encoding.hasType = function hasType(map, type) {
  assert(Buffer.isBuffer(map));
  assert((type & 0xffff) === type);

  let i = 0;

  while (i < map.length) {
    assert(i + 2 <= map.length);

    const win = map[i++];
    const len = map[i++];

    assert(len > 0 && len <= 32);
    assert(i + len <= map.length);

    if (win * 256 > type)
      break;

    if ((win + 1) * 256 <= type) {
      i += len;
      continue;
    }

    if (type < (win * 256) + len * 8) {
      const oct = type >>> 3;
      const bit = (type & 7);
      const ch = map[i + oct];
      const mask = 1 << (7 - bit);

      if (ch & mask)
        return true;
    }

    i += len;
  }

  return false;
};

/*
 * Helpers
 */

function isDigit(ch) {
  assert((ch & 0xff) === ch);
  ch -= 0x30;
  return ch >= 0 && ch <= 9;
}

function toByte(n, i) {
  assert(Buffer.isBuffer(n));
  assert((i >>> 0) === i);
  const hi = (n[i + 0] - 0x30) * 100;
  const md = (n[i + 1] - 0x30) * 10;
  const lo = (n[i + 2] - 0x30) * 1;
  return hi + md + lo;
}

function toDDD(b) {
  const d = b.toString(10);
  switch (d.length) {
    case 1:
      return `00${d}`;
    case 2:
      return `0${d}`;
    case 3:
      return `${d}`;
    default:
      throw new Error();
  }
}

function compare(a, b) {
  return (a | 0) - (b | 0);
}
