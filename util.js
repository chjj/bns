'use strict';

exports.isDigit = function isDigit(ch) {
  assert((ch & 0xff) === ch);
  ch -= 0x30;
  return ch >= 0 && ch <= 9;
};

exports.dddToByte = function dddToByte(bs, i) {
  assert(Buffer.isBuffer(bs));
  assert((i >>> 0) === i);
  return (bs[i] - 0x30) * 100 + (bs[i + 1] - 0x30) * 10 + (bs[i + 2] - 0x30);
};
