/* eslint-env mocha */
/* eslint prefer-arrow-callback: "off" */

'use strict';

const assert = require('bsert');
const hsig = require('../lib/hsig');
const wire = require('../lib/wire');

const {
  types,
  Message,
  Question,
  Record
} = wire;

describe('HSIG', function() {
  it('should sign and verify message', () => {
    const msg = new Message();

    msg.qr = true;
    msg.ad = true;

    msg.question.push(Question.fromString('example.com. IN A'));
    msg.answer.push(Record.fromString('example.com. 300 IN A 172.217.0.46'));

    const priv = hsig.createPrivate();
    const pub = hsig.createPublic(priv);
    const key = hsig.createKey(pub);
    assert(key);

    const msgRaw = msg.compress();
    const signedRaw = hsig.sign(msgRaw, priv);

    const signed = Message.decode(signedRaw);
    assert(signed.sig0 instanceof Record);
    assert(signed.sig0.type === types.SIG);
    assert(signed.sig0.data.typeCovered === 0);
    assert(signed.sig0.data.algorithm === 253); // PRIVATEDNS
    assert(signed.sig0.data.signature.length === 64);

    assert(hsig.verify(signedRaw, pub));
  });
});
