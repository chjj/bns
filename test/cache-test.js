/* eslint-env mocha */
/* eslint prefer-arrow-callback: "off" */

'use strict';

const assert = require('./util/assert');
const wire = require('../lib/wire');
const Cache = require('../lib/cache');

const {
  types,
  Message,
  Question,
  Record,
  ARecord
} = wire;

describe('Cache', function() {
  it('should cache message', () => {
    const qs = new Question('example.com.', 'A');
    const msg = new Message();

    msg.qr = true;
    msg.ad = true;
    msg.question.push(qs);

    const rr = new Record();
    const rd = new ARecord();

    rr.name = 'google.com.';
    rr.type = types.A;
    rr.ttl = 3600;
    rr.data = rd;
    rd.address = '127.0.0.1';

    msg.answer.push(rr);

    const cache = new Cache();

    cache.insert(qs, 'com.', msg, true);
    assert.strictEqual(cache.size, 255);

    cache.insert(qs, 'com.', msg, true);
    assert.strictEqual(cache.size, 313);

    const msg2 = cache.hit(qs, 'com.');
    assert(msg2);

    assert.bufferEqual(msg2.encode(), msg.encode());
  });
});
