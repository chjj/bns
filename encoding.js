'use strict';

const assert = require('assert');
const {EncodingError} = require('bufio');

exports.sizeName = function sizeName(name, map, cmp) {
  const [off] = exports.writeName(null, name, 0, map, cmp);
  return off;
};

exports.writeName = function writeName(data, name, off, map, cmp) {
  if (cmp == null)
    cmp = false;

  assert(data == null || Buffer.isBuffer(data));
  assert(typeof name === 'string')
  assert((off >>> 0) === off);
  assert(map == null || (map instanceof Map));
  assert(typeof cmp === 'boolean');
  assert(name.length <= 254);

  let len = 256;

  if (data)
    len = data.length;

  let nl = name.length;

  if (nl === 0)
    return off;

  if (!data) {
    if (name[nl - 1] !== '.') {
      name += '.';
      nl += 1;
    }
  } else {
    if (name[nl - 1] !== '.')
      throw new EncodingError(0, 'No dot');
  }

  const n = Buffer.from(name, 'ascii');

  if (n.length !== nl)
    throw new EncodingError(0, 'Bad ascii string');

  let pos = -1;
  let ptr = -1;
  let begin = 0;
  let fresh = true;
  let escaped = false;
  let labels = 0;

  for (let i = 0; i < nl; i++) {
    if (n[i] === 0x5c /*\\*/) {
      for (let j = i; j < nl - 1; j++)
        n[j] = n[j + 1];

      nl -= 1;

      if (off + 1 > len)
        throw new EncodingError(off, 'EOF');

      if (i + 2 < nl
          && isDigit(n[i + 0])
          && isDigit(n[i + 1])
          && isDigit(n[i + 2])) {
        n[i] = toByte(n, i);
        for (let j = i + 1; j < nl - 2; j++)
          n[j] = n[j + 2];
        nl -= 2;
      }

      escaped = true;
      fresh = false;

      continue;
    }

    if (n[i] === 0x2e /*.*/) {
      if (i > 0 && n[i - 1] === 0x2e /*.*/ && !escaped)
        throw new EncodingError(off, 'Multiple dots');

      if (i - begin >= (1 << 6))
        throw new EncodingError(off, 'Bad top bits');

      if (off + 1 > len)
        throw new EncodingError(off, 'EOF');

      if (data)
        data[off] = (i - begin) & 0xff;

      let offset = off;

      off += 1;

      for (let j = begin; j < i; j++) {
        if (off + 1 > len)
          throw new EncodingError(off, 'EOF');

        if (data)
          data[off] = n[j];

        off += 1;
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

  if (n.length === 1 && n[0] === 0x2e /*.*/)
    return [off, labels];

  if (ptr !== -1) {
    if (data)
      data.writeUInt16BE(pos, ptr ^ 0xc000, true);
    off = pos + 2;
    return [off, labels];
  }

  if (data && off < len)
    data[off] = 0;

  off += 1;

  return [off, labels];
};

exports.readName = function readName(data, off) {
  assert(Buffer.isBuffer(data));
  assert((off >>> 0) === off);

  let name = '';
  let res = 0;
  let max = 255;
  let ptr = 0;

outer:
  for (;;) {
    if (off >= data.length)
      throw new EncodingError(off, 'EOF');

    let c = data[off];

    off += 1;

    switch (c & 0xc0) {
      case 0x00: {
        if (c === 0x00)
          break outer;

        if (off + c > data.length)
          throw new EncodingError(off, 'EOF');

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
              name += '\\' + String.fromCharCode(b);
              max += 1;
              break;
            }
            default: {
              if (b < 32 || b >= 127) {
                let bc = b.toString(10);
                while (bc.length < 3)
                  bc = '0' + bc;
                name += '\\' + bc;
                max += 3;
              } else {
                name += String.fromCharCode(b);
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
        throw new EncodingError(off, 'Bad character');
      }
    }
  }

  if (ptr === 0)
    res = off;

  if (name.length === 0)
    name = '.';

  if (name.length >= max)
    throw new EncodingError(off, 'Max name length exceeded');

  return [res, name];
};

exports.writeNameBW = function writeNameBW(bw, name, map, cmp) {
  const {data, offset} = bw;
  const [off, labels] = exports.writeName(data, name, offset, map, cmp);
  bw.offset = off;
  return labels;
};

exports.readNameBR = function readNameBR(br) {
  const [off, name] = exports.readName(br.data, br.offset);
  br.offset = off;
  return name;
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
