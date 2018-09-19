/* eslint-env mocha */
/* eslint prefer-arrow-callback: "off" */

'use strict';

const assert = require('./util/assert');
const sig0 = require('../lib/sig0');
const wire = require('../lib/wire');

const {
  types,
  algs,
  Message,
  Question,
  Record
} = wire;

describe('SIG(0)', function() {
  it('should sign and verify message', () => {
    const msg = new Message();

    msg.qr = true;
    msg.ad = true;

    msg.question.push(Question.fromString('example.com. IN A'));
    msg.answer.push(Record.fromString('example.com. 300 IN A 172.217.0.46'));

    const priv = sig0.createPrivate(algs.RSASHA256, 1024);
    const pub = sig0.createPublic(algs.RSASHA256, priv);
    const key = sig0.createKey(algs.RSASHA256, pub);

    const msgRaw = msg.compress();
    const signedRaw = sig0.sign(msgRaw, key, priv);

    const signed = Message.decode(signedRaw);
    assert(signed.sig0 instanceof Record);
    assert(signed.sig0.type === types.SIG);
    assert(signed.sig0.data.typeCovered === 0);
    assert(signed.sig0.data.algorithm === algs.RSASHA256);
    assert(signed.sig0.data.signature.length === 1024 / 8);

    assert(sig0.verify(signedRaw, key));
  });
});
