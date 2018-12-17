/* eslint-env mocha */
/* eslint prefer-arrow-callback: "off" */

'use strict';

const assert = require('bsert');
const Path = require('path');
const fs = require('fs');
const wire = require('../lib/wire');
const opk = require('../lib/openpgpkey');
const {Record, types} = wire;

const OPK_FILE = Path.resolve(__dirname, 'data', 'openpgpkey.zone');
const opkText = fs.readFileSync(OPK_FILE, 'utf8');

function fromBase64(str) {
  return Buffer.from(str.replace(/\s+/g, ''), 'base64');
}

describe('OPENPGPKEY', function() {
  it('should serialize email', () => {
    const name1 = opk.encodeEmail('slippinjimmy@example.com.', 256);

    assert.strictEqual(name1,
      'ae91629c1142f97683521f4b70cade48e95202aff15c16f0fdf34779'
      + '._openpgpkey.example.com.');

    const name2 = opk.encodeEmail('slippinjimmy@example.com.', 224);

    assert.strictEqual(name2,
      'b33f5890ccb3ea7d9c91a6459d75a8a27eb9e894ab25fd2b5fc26aef'
      + '._openpgpkey.example.com.');

    assert(opk.isName(name1));
    assert(opk.isName(name2));

    const data1 = opk.decodeName(name1);
    assert.strictEqual(data1.name, 'example.com.');
    assert.strictEqual(data1.hash.length, 28);

    const data2 = opk.decodeName(name1);
    assert.strictEqual(data2.name, 'example.com.');
    assert.strictEqual(data2.hash.length, 28);
  });

  it('should create openpgpkey record', () => {
    const key = Buffer.alloc(32, 0x00);
    const rr = opk.create(key, 'slippinjimmy@example.com.', { ttl: 3600 });
    assert(rr.type === types.OPENPGPKEY);
    assert(opk.verify(rr, key));
    const fake = Buffer.alloc(32, 0x00);
    fake[0] ^= 1;
    assert(!opk.verify(rr, fake));
  });

  it('should create openpgpkey record', () => {
    // $ dig.js zbyszek@fedoraproject.org OPENPGPKEY -b 224
    const key = fromBase64(`
      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
    `);

    const rr = Record.fromString(opkText);
    assert(rr.type === types.OPENPGPKEY);
    assert(opk.verify(rr, key));
  });
});
