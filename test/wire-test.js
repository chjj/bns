/* eslint-env mocha */
/* eslint prefer-arrow-callback: "off" */

'use strict';

const assert = require('bsert');
const Path = require('path');
const fs = require('bfile');
const wire = require('../lib/wire');
const {Message, Record} = wire;

const ROOT_ZONE = Path.resolve(__dirname, 'data', 'root.zone');
const ROOT_JSON = Path.resolve(__dirname, 'data', 'root.json');
const MSG_RAW = Path.resolve(__dirname, 'data', 'msg-raw.json');
const MSG_JSON = Path.resolve(__dirname, 'data', 'msg-json.json');

describe('Wire', function() {
  this.timeout(20000);

  describe('Root Zone File', function() {
    let rootZone = null;
    let rootJson = null;
    let rootRaw = null;

    it('should parse root zone file', () => {
      rootZone = wire.fromZone(fs.readFileSync(ROOT_ZONE, 'utf8'));
      rootJson = JSON.parse(fs.readFileSync(ROOT_JSON, 'utf8'));
      rootRaw = rootJson.map(hex => Buffer.from(hex, 'hex'));

      assert.strictEqual(rootZone.length, 22540);
      assert.strictEqual(rootJson.length, 22540);
      assert.strictEqual(rootRaw.length, 22540);

      assert.strictEqual(rootZone.length, rootJson.length);
      assert.strictEqual(rootZone.length, rootRaw.length);
    });

    it('should compare zone to raw', () => {
      for (let i = 0; i < rootZone.length; i++)
        assert.bufferEqual(rootZone[i].encode(), rootRaw[i]);
    });

    it('should compare raw to zone', () => {
      for (let i = 0; i < rootZone.length; i++)
        assert.deepStrictEqual(Record.decode(rootRaw[i]), rootZone[i]);
    });

    it('should reserialize', () => {
      for (let i = 0; i < rootZone.length; i++) {
        const rr = rootZone[i];
        assert.deepStrictEqual(Record.decode(rr.encode()), rr);
      }
    });

    it('should reencode', () => {
      for (let i = 0; i < rootZone.length; i++) {
        const rr = rootZone[i];

        assert.deepStrictEqual(Record.fromString(rr.toString()), rr);
      }
    });

    it('should rejson', () => {
      for (let i = 0; i < rootZone.length; i++) {
        const rr = rootZone[i];
        assert.deepStrictEqual(Record.fromJSON(rr.toJSON()), rr);
      }
    });
  });

  describe('Messages', function() {
    const msgJson_ = JSON.parse(fs.readFileSync(MSG_JSON, 'utf8'));
    const msgRaw_ = JSON.parse(fs.readFileSync(MSG_RAW, 'utf8'));

    let msgJson = null;
    let msgRaw = null;

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
      msgJson = msgJson_.map(json => Message.fromJSON(json));
      msgRaw = msgRaw_.map(hex => Buffer.from(hex, 'hex'));

      assert.strictEqual(msgJson_.length, 280);
      assert.strictEqual(msgRaw_.length, 280);
      assert.strictEqual(msgJson.length, 280);
      assert.strictEqual(msgRaw.length, 280);
      assert.strictEqual(msgJson.length, msgRaw.length);
    });

    it('should compare raw to json', () => {
      for (let i = 0; i < msgJson.length; i++)
        deepStrictEqual(Message.decode(msgRaw[i]), msgJson[i]);
    });

    it('should reserialize', () => {
      for (let i = 0; i < msgJson.length; i++) {
        const msg = msgJson[i];
        deepStrictEqual(Message.decode(msg.encode()), msg);
      }
    });

    it('should compress', () => {
      for (let i = 0; i < msgJson.length; i++) {
        const msg = msgJson[i];
        deepStrictEqual(Message.decode(msg.compress()), msg);
      }
    });

    it('should not compress next domain in NSEC records', () => {
      const msg = msgJson[279];
      const raw = msgRaw[279];
      assert(msg instanceof Message);
      assert(raw instanceof Buffer);
      assert.strictEqual(msg.id, 63591);
      assert(raw.equals(msg.compress()));
    });

    it('should reencode', () => {
      for (let i = 0; i < msgJson.length; i++) {
        const msg = msgJson[i];
        deepStrictEqual(Message.fromString(msg.toString()), msg);
      }
    });

    it('should rejson', () => {
      for (let i = 0; i < msgJson.length; i++) {
        const msg = msgJson[i];
        deepStrictEqual(Message.fromJSON(msg.toJSON()), msg);
      }
    });
  });
});
