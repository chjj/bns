/* eslint-env mocha */
/* eslint prefer-arrow-callback: "off" */

'use strict';

const assert = require('./util/assert');
const tsig = require('../lib/tsig');
const wire = require('../lib/wire');
const {algs} = tsig;

const {
  types,
  Message,
  Question,
  Record
} = wire;

describe('TSIG', function() {
  it('should sign and verify message', () => {
    const msg = new Message();

    msg.qr = true;
    msg.ad = true;

    msg.question.push(Question.fromString('example.com. IN A'));
    msg.answer.push(Record.fromString('example.com. 300 IN A 172.217.0.46'));

    const secret = Buffer.alloc(32, 0x01);

    const msgRaw = msg.compress();
    const signedRaw = tsig.sign(msgRaw, algs.SHA256, secret, null, false);

    const signed = Message.decode(signedRaw);
    assert(signed.tsig instanceof Record);
    assert(signed.tsig.type === types.TSIG);
    assert(signed.tsig.data.algorithm === algs.SHA256);
    assert(signed.tsig.data.mac.length === 32);

    assert(tsig.verify(signedRaw, secret, null, false));

    secret[0] ^= 1;
    assert(!tsig.verify(signedRaw, secret, null, false));
  });

  it('should sign and verify message (timersOnly)', () => {
    const msg = new Message();

    msg.qr = true;
    msg.ad = true;

    msg.question.push(Question.fromString('example.com. IN A'));
    msg.answer.push(Record.fromString('example.com. 300 IN A 172.217.0.46'));

    const secret = Buffer.alloc(32, 0x01);

    const msgRaw = msg.compress();
    const signedRaw = tsig.sign(msgRaw, algs.SHA256, secret, null, true);

    const signed = Message.decode(signedRaw);
    assert(signed.tsig instanceof Record);
    assert(signed.tsig.type === types.TSIG);
    assert(signed.tsig.data.algorithm === algs.SHA256);
    assert(signed.tsig.data.mac.length === 32);

    assert(tsig.verify(signedRaw, secret, null, true));

    secret[0] ^= 1;
    assert(!tsig.verify(signedRaw, secret, null, true));
  });
});
