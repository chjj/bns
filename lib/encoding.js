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

/*
 * Constants
 */

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

const POOL1 = Buffer.allocUnsafe(MAX_NAME_SIZE * 4);
const POOL2 = Buffer.allocUnsafe(MAX_NAME_SIZE * 4);

/*
 * Encoding
 */

const encoding = exports;

encoding.sizeName = function sizeName(name, map, insert, cmp) {
  const [off] = encoding.writeName(null, name, 0, map, insert, cmp);
  return off;
};

encoding.writeName = function writeName(data, name, off, map, insert, cmp) {
  if (data == null)
    data = null;

  if (map == null)
    map = null;

  if (insert == null)
    insert = map != null;

  if (cmp == null)
    cmp = map != null;

  assert(data === null || Buffer.isBuffer(data));
  assert(typeof name === 'string');
  assert((off >>> 0) === off);
  assert(map === null || (map instanceof Map));
  assert(typeof insert === 'boolean');
  assert(typeof cmp === 'boolean');

  let nl = name.length;

  if (nl === 0 || name[nl - 1] !== '.')
    throw new EncodingError(0, 'No dot');

  if (nl > MAX_NAME_SIZE * 4)
    throw new EncodingError(0, 'Name too large');

  const n = POOL1;

  if (n.write(name, 'ascii') !== nl)
    throw new EncodingError(0, 'Invalid string');

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

      if (isDigits(n, i, nl)) {
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
        throw new EncodingError(off, 'Maximum label size exceeded');

      if (data) {
        if (off + 1 > data.length)
          throw new EncodingError(off, 'EOF');
        data[off] = size;
      }

      if (cmp && !fresh) {
        name = n.toString('ascii', 0, nl);
        fresh = true;
      }

      if (map) {
        const s = name.substring(begin);
        if (s !== '.') {
          const p = map.get(s);
          if (p == null) {
            if (insert && off < (2 << 13))
              map.set(s, off);
          } else {
            if (cmp && ptr === -1) {
              ptr = p;
              pos = off;
              break;
            }
          }
        }
      }

      off += 1;

      if (data) {
        if (off + size > data.length)
          throw new EncodingError(off, 'EOF');
        assert(n.copy(data, off, begin, i) === size);
      }

      off += size;

      labels += 1;
      begin = i + 1;
    }

    escaped = false;
  }

  if (nl > MAX_NAME_SIZE)
    throw new EncodingError(off, 'Maximum name size exceeded');

  if (nl === 1 && n[0] === 0x2e /*.*/)
    return [off, labels];

  if (ptr !== -1) {
    off = pos;

    if (data) {
      if (off + 2 > data.length)
        throw new EncodingError(off, 'EOF');
      data.writeUInt16BE(ptr ^ 0xc000, off, true);
    }

    off += 2;

    return [off, labels];
  }

  if (data) {
    if (off + 1 > data.length)
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
          throw new EncodingError(off, 'Maximum label size exceeded');

        if (off + c > data.length)
          throw new EncodingError(off, 'EOF');

        if (name.length + c + 1 > max)
          throw new EncodingError(off, 'Maximum name length exceeded');

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

encoding.writeNameBW = function writeNameBW(bw, name, map, insert, cmp) {
  assert(bw);
  const {data, offset} = bw;
  const [off, labels] =
    encoding.writeName(data, name, offset, map, insert, cmp);
  bw.offset = off;
  return labels;
};

encoding.readNameBR = function readNameBR(br) {
  assert(br);
  const [off, name] = encoding.readName(br.data, br.offset);
  br.offset = off;
  return name;
};

encoding.packName = function packName(name) {
  const size = encoding.sizeName(name, null, false, false);
  const data = Buffer.allocUnsafe(size);
  encoding.writeName(data, name, 0, null, false, false);
  return data;
};

encoding.unpackName = function unpackName(data) {
  const [, name] = encoding.readName(data, 0);
  return name;
};

encoding.isName = function isName(name) {
  assert(typeof name === 'string');

  let nl = name.length;

  if (nl === 0 || name[nl - 1] !== '.')
    return false;

  if (nl > MAX_NAME_SIZE * 4)
    return false;

  const n = POOL1;

  if (n.write(name, 'ascii') !== nl)
    return false;

  let escaped = false;
  let begin = 0;

  for (let i = 0; i < nl; i++) {
    if (n[i] === 0x5c /*\\*/) {
      for (let j = i; j < nl - 1; j++)
        n[j] = n[j + 1];

      nl -= 1;

      if (isDigits(n, i, nl)) {
        n[i] = toByte(n, i);

        for (let j = i + 1; j < nl - 2; j++)
          n[j] = n[j + 2];

        nl -= 2;

        if (n[i] >= 0x20 && n[i] <= 0x7e)
          return false;
      } else {
        switch (n[i]) {
          case 0x2e /*.*/:
          case 0x28 /*(*/:
          case 0x29 /*)*/:
          case 0x3b /*;*/:
          case 0x20 /* */:
          case 0x40 /*@*/:
          case 0x22 /*"*/:
          case 0x5c /*\\*/: {
            break;
          }
          default:
            return false;
        }
      }

      escaped = n[i] === 0x2e;

      continue;
    }

    switch (n[i]) {
      case 0x28 /*(*/:
      case 0x29 /*)*/:
      case 0x3b /*;*/:
      case 0x20 /* */:
      case 0x40 /*@*/:
      case 0x22 /*"*/:
      case 0x5c /*\\*/: {
        return false;
      }
      default:
        if (n[i] < 0x20 || n[i] > 0x7e)
          return false;
        break;
    }

    if (n[i] === 0x2e /*.*/) {
      if (i > 0 && n[i - 1] === 0x2e /*.*/ && !escaped)
        return false;

      const size = i - begin;

      if (size > MAX_LABEL_SIZE)
        return false;

      begin = i + 1;
    }

    escaped = false;
  }

  if (nl > MAX_NAME_SIZE)
    return false;

  return true;
};

encoding.toName = function toName(name, enc) {
  if (enc == null)
    enc = 'utf8';

  assert(typeof enc === 'string');

  if (Buffer.isBuffer(name)) {
    if (name.length + 1 > MAX_NAME_SIZE)
      throw new EncodingError(0, 'Name too large');

    name = name.toString('hex');
    enc = 'hex';
  }

  assert(typeof name === 'string');

  let str = encoding._escapeString(name, false, enc);

  if (str.length === 0 || str[str.length - 1] !== '.')
    str += '.';

  const buf = POOL2;
  const [len] = encoding.writeName(buf, str, 0, null, false, false);

  if (len >= buf.length)
    throw new EncodingError(0, 'Name too large');

  const data = buf.slice(0, len);

  return encoding.readName(data, 0)[1];
};

encoding.fromName = function fromName(name, enc) {
  if (enc == null)
    enc = 'utf8';

  assert(encoding.isName(name));
  assert(typeof enc === 'string');

  return encoding._unescapeString(name, false, enc);
};

encoding.sizeRawString = function sizeRawString(str) {
  return encoding.writeRawString(null, str, 0);
};

encoding.writeRawString = function writeRawString(data, str, off) {
  if (data == null)
    data = null;

  assert(data === null || Buffer.isBuffer(data));
  assert(typeof str === 'string');
  assert((off >>> 0) === off);

  let sl = str.length;

  if (sl > MAX_NAME_SIZE * 4)
    throw new EncodingError(0, 'String too large');

  const s = POOL1;

  if (s.write(str, 'ascii') !== sl)
    throw new EncodingError(0, 'Invalid string');

  for (let i = 0; i < sl; i++) {
    if (s[i] === 0x5c /*\\*/) {
      for (let j = i; j < sl - 1; j++)
        s[j] = s[j + 1];

      sl -= 1;

      if (isDigits(s, i, sl)) {
        s[i] = toByte(s, i);
        for (let j = i + 1; j < sl - 2; j++)
          s[j] = s[j + 2];
        sl -= 2;
      }
    }

    if (data) {
      if (off + 1 > data.length)
        throw new EncodingError(off, 'EOF');
      data[off] = s[i];
    }

    off += 1;
  }

  if (sl > MAX_NAME_SIZE)
    throw new EncodingError(off, 'Maximum string size exceeded');

  return off;
};

encoding.readRawString = function readRawString(data, off, len, nsp) {
  if (nsp == null)
    nsp = false;

  assert(Buffer.isBuffer(data));
  assert((off >>> 0) === off);
  assert((len >>> 0) === len);
  assert(typeof nsp === 'boolean');

  if (len > MAX_NAME_SIZE)
    throw new EncodingError(off, 'Maximum string size exceeded');

  if (off + len > data.length)
    throw new EncodingError(off, 'EOF');

  const SPACE = 0x20 + (nsp ? 1 : 0);
  const start = off;
  const end = off + len;

  let str = '';

  for (let i = start; i < end; i++) {
    const b = data[i];

    switch (b) {
      case 0x22 /*"*/:
      case 0x5c /*\\*/:
        str += '\\' + ASCII[b];
        break;
      default:
        if (b < SPACE || b > 0x7e)
          str += '\\' + toDDD(b);
        else
          str += ASCII[b];
        break;
    }
  }

  return [end, str];
};

encoding.packRawString = function packRawString(str) {
  const size = encoding.sizeRawString(str);
  const data = Buffer.allocUnsafe(size);
  encoding.writeRawString(data, str, 0);
  return data;
};

encoding.unpackRawString = function unpackRawString(data, nsp) {
  assert(data);
  const [, str] = encoding.readRawString(data, 0, data.length, nsp);
  return str;
};

encoding.writeRawStringBW = function writeRawStringBW(bw, str) {
  assert(bw);
  const {data, offset} = bw;
  bw.offset = encoding.writeRawString(data, str, offset);
  return bw;
};

encoding.readRawStringBR = function readRawStringBR(br, len, nsp) {
  assert(br);
  const [off, str] = encoding.readRawString(br.data, br.offset, len, nsp);
  br.offset = off;
  return str;
};

encoding.sizeString = function sizeString(str) {
  return encoding.writeString(null, str, 0);
};

encoding.writeString = function writeString(data, str, off) {
  if (data == null)
    data = null;

  assert(data === null || Buffer.isBuffer(data));
  assert(typeof str === 'string');
  assert((off >>> 0) === off);

  const start = off;

  if (data) {
    if (off + 1 > data.length)
      throw new EncodingError(off, 'EOF');
    data[off] = 0;
  }

  off += 1;

  const offset = encoding.writeRawString(data, str, off);
  const size = offset - off;

  if (data)
    data[start] = size;

  off += size;

  return off;
};

encoding.readString = function readString(data, off, nsp) {
  assert(Buffer.isBuffer(data));
  assert((off >>> 0) === off);

  if (off + 1 > data.length)
    throw new EncodingError(off, 'EOF');

  const len = data[off];

  off += 1;

  return encoding.readRawString(data, off, len, nsp);
};

encoding.packString = function packString(str) {
  const size = encoding.sizeString(str);
  const data = Buffer.allocUnsafe(size);
  encoding.writeString(data, str, 0);
  return data;
};

encoding.unpackString = function unpackString(data, nsp) {
  const [, str] = encoding.readString(data, 0, nsp);
  return str;
};

encoding.isString = function isString(str, nsp) {
  if (nsp == null)
    nsp = false;

  assert(typeof str === 'string');
  assert(typeof nsp === 'boolean');

  let sl = str.length;

  if (sl > MAX_NAME_SIZE * 4)
    return false;

  const SPACE = 0x20 + (nsp ? 1 : 0);
  const s = POOL1;

  if (s.write(str, 'ascii') !== sl)
    return false;

  for (let i = 0; i < sl; i++) {
    if (s[i] === 0x5c /*\\*/) {
      for (let j = i; j < sl - 1; j++)
        s[j] = s[j + 1];

      sl -= 1;

      if (isDigits(s, i, sl)) {
        s[i] = toByte(s, i);

        for (let j = i + 1; j < sl - 2; j++)
          s[j] = s[j + 2];

        sl -= 2;

        if (s[i] >= SPACE && s[i] <= 0x7e)
          return false;
      } else {
        switch (s[i]) {
          case 0x22 /*"*/:
          case 0x5c /*\\*/:
            break;
          default:
            return false;
        }
      }

      continue;
    }

    switch (s[i]) {
      case 0x22 /*"*/:
      case 0x5c /*\\*/:
        return false;
      default:
        if (s[i] < SPACE || s[i] > 0x7e)
          return false;
        break;
    }
  }

  if (sl > MAX_NAME_SIZE)
    return false;

  return true;
};

encoding._escapeString = function _escapeString(str, nsp, enc) {
  if (nsp == null)
    nsp = false;

  if (enc == null)
    enc = 'utf8';

  assert(typeof nsp === 'boolean');

  let buf, len;

  if (Buffer.isBuffer(str)) {
    buf = str;
    len = buf.length;

    if (len > MAX_NAME_SIZE)
      throw new EncodingError(0, 'String too large');
  } else {
    assert(typeof str === 'string');
    assert(typeof enc === 'string');

    buf = POOL2;
    len = buf.write(str, enc);

    if (len >= buf.length)
      throw new EncodingError(0, 'String too large');
  }

  return encoding.readRawString(buf, 0, len, nsp)[1];
};

encoding.toString = function toString(str, nsp, enc) {
  return encoding._escapeString(str, nsp, enc);
};

encoding._unescapeString = function _unescapeString(str, nsp, enc) {
  if (nsp == null)
    nsp = false;

  if (enc == null)
    enc = 'utf8';

  assert(typeof str === 'string');
  assert(typeof enc === 'string');

  const buf = POOL2;
  const len = encoding.writeRawString(buf, str, 0);

  if (enc === 'buffer')
    return Buffer.from(buf.slice(0, len));

  return buf.toString(enc, 0, len);
};

encoding.fromString = function fromString(str, nsp, enc) {
  assert(encoding.isString(str, nsp));
  return encoding._unescapeString(str, nsp, enc);
};

encoding.writeStringBW = function writeStringBW(bw, str) {
  assert(bw);
  const {data, offset} = bw;
  bw.offset = encoding.writeString(data, str, offset);
  return bw;
};

encoding.readStringBR = function readStringBR(br, nsp) {
  assert(br);
  const [off, str] = encoding.readString(br.data, br.offset, nsp);
  br.offset = off;
  return str;
};

encoding.reverse = function reverse(addr) {
  const ip = IP.toBuffer(addr);

  let name = '';
  let i = 15;

  if (IP.isIPv4(ip)) {
    for (; i >= 12; i--) {
      const ch = ip[i];
      name += ch.toString(10);
      name += '.';
    }

    return `${name}in-addr.arpa.`;
  }

  for (; i >= 0; i--) {
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

function isDigit(num) {
  return num >= 0x30 && num <= 0x39;
}

function isDigits(buf, off, len) {
  assert(Buffer.isBuffer(buf));
  assert((off >>> 0) === off);
  assert((len >>> 0) === len);
  assert(len <= buf.length);

  if (off + 3 > len)
    return false;

  if (!isDigit(buf[off + 0]))
    return false;

  if (!isDigit(buf[off + 1]))
    return false;

  if (!isDigit(buf[off + 2]))
    return false;

  return true;
}

function toByte(buf, off) {
  assert(Buffer.isBuffer(buf));
  assert((off >>> 0) === off);
  assert(off + 3 <= buf.length);

  const hi = (buf[off + 0] - 0x30) * 100;
  const md = (buf[off + 1] - 0x30) * 10;
  const lo = (buf[off + 2] - 0x30) * 1;

  return hi + md + lo;
}

function toDDD(ch) {
  assert((ch & 0xff) === ch);

  const str = ch.toString(10);

  switch (str.length) {
    case 1:
      return `00${str}`;
    case 2:
      return `0${str}`;
    case 3:
      return `${str}`;
    default:
      throw new Error('Invalid byte.');
  }
}

function compare(a, b) {
  return (a | 0) - (b | 0);
}
