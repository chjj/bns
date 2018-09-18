/* eslint-env mocha */
/* eslint prefer-arrow-callback: "off" */

'use strict';

const assert = require('./util/assert');
const Path = require('path');
const fs = require('bfile');
const wire = require('../lib/wire');
const {Message, Record} = wire;

const ROOT_ZONE = Path.resolve(__dirname, 'data', 'root.zone');
const ROOT_JSON = Path.resolve(__dirname, 'data', 'root.json');
const MSG_RAW = Path.resolve(__dirname, 'data', 'msg-raw.json');
const MSG_JSON = Path.resolve(__dirname, 'data', 'msg-json.json');

describe('Wire', function() {
  describe('Root Zone File', function() {
    const rootZone = wire.fromZone(fs.readFileSync(ROOT_ZONE, 'utf8'));
    const rootJson = JSON.parse(fs.readFileSync(ROOT_JSON, 'utf8'));
    const rootRaw = rootJson.map(hex => Buffer.from(hex, 'hex'));

    assert.strictEqual(rootZone.length, 22540);
    assert.strictEqual(rootJson.length, 22540);
    assert.strictEqual(rootRaw.length, 22540);

    it('should parse root zone file', () => {
      assert.strictEqual(rootZone.length, rootJson.length);
      assert.strictEqual(rootZone.length, rootRaw.length);
    });

    for (let i = 0; i < rootZone.length; i++) {
      const rr = rootZone[i];

      it(`should compare zone to raw (${rr.name}/${rr.type}) (${i})`, () => {
        assert.bufferEqual(rootZone[i].encode(), rootRaw[i]);
      });
    }

    for (let i = 0; i < rootZone.length; i++) {
      const rr = rootZone[i];

      it(`should compare raw to zone (${rr.name}/${rr.type}) (${i})`, () => {
        assert.deepStrictEqual(Record.decode(rootRaw[i]), rootZone[i]);
      });
    }

    for (let i = 0; i < rootZone.length; i++) {
      const rr = rootZone[i];

      it(`should reserialize (${rr.name}/${rr.type}) (${i})`, () => {
        assert.deepStrictEqual(Record.decode(rr.encode()), rr);
      });
    }

    for (let i = 0; i < rootZone.length; i++) {
      const rr = rootZone[i];

      it(`should reencode (${rr.name}/${rr.type}) (${i})`, () => {
        assert.deepStrictEqual(Record.fromString(rr.toString()), rr);
      });
    }

    for (let i = 0; i < rootZone.length; i++) {
      const rr = rootZone[i];

      it(`should rejson (${rr.name}/${rr.type}) (${i})`, () => {
        assert.deepStrictEqual(Record.fromJSON(rr.toJSON()), rr);
      });
    }
  });

  describe('Messages', function() {
    const msgJson_ = JSON.parse(fs.readFileSync(MSG_JSON, 'utf8'));
    const msgRaw_ = JSON.parse(fs.readFileSync(MSG_RAW, 'utf8'));
    const msgJson = msgJson_.map(json => Message.fromJSON(json));
    const msgRaw = msgRaw_.map(hex => Buffer.from(hex, 'hex'));

    assert.strictEqual(msgJson_.length, 279);
    assert.strictEqual(msgRaw_.length, 279);
    assert.strictEqual(msgJson.length, 279);
    assert.strictEqual(msgRaw.length, 279);

    const clean = (msg) => {
      assert(msg instanceof Message);
      msg.size = 0;
      msg.malformed = false;
      msg.trailing = Buffer.alloc(0);
    };

    const deepStrictEqual = (x, y) => {
      assert.deepStrictEqual(clean(x), clean(y));
    };

    it('should parse messages', () => {
      assert.strictEqual(msgJson.length, msgRaw.length);
    });

    for (let i = 0; i < msgJson.length; i++) {
      const msg = msgJson[i];
      const qs = msg.question[0];

      it(`should compare raw to json (${qs.name}/${qs.type}) (${i})`, () => {
        deepStrictEqual(Message.decode(msgRaw[i]), msgJson[i]);
      });
    }

    for (let i = 0; i < msgJson.length; i++) {
      const msg = msgJson[i];
      const qs = msg.question[0];

      it(`should reserialize (${qs.name}/${qs.type}) (${i})`, () => {
        deepStrictEqual(Message.decode(msg.encode()), msg);
      });
    }

    for (let i = 0; i < msgJson.length; i++) {
      const msg = msgJson[i];
      const qs = msg.question[0];

      it(`should compress (${qs.name}/${qs.type}) (${i})`, () => {
        deepStrictEqual(Message.decode(msg.compress()), msg);
      });
    }

    for (let i = 0; i < msgJson.length; i++) {
      const msg = msgJson[i];
      const qs = msg.question[0];

      it(`should reencode (${qs.name}/${qs.type}) (${i})`, () => {
        deepStrictEqual(Message.fromString(msg.toString()), msg);
      });
    }

    for (let i = 0; i < msgJson.length; i++) {
      const msg = msgJson[i];
      const qs = msg.question[0];

      it(`should rejson (${qs.name}/${qs.type}) (${i})`, () => {
        deepStrictEqual(Message.fromJSON(msg.toJSON()), msg);
      });
    }
  });
});
