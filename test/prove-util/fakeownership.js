'use strict';

const path = require('path');
const Ownership = require('../../lib/ownership');
const {Record, Message} = require('../../lib/wire');
const Zone = require('../../lib/zone');

const KSK = Record.fromString(
  '. IN DS 63077 15 2 ' +
  '433633AAAE8780F7EA8C46D403195A3BB58992D64B7C79E61EAB4D7EC336D077'
);
const ROOT_ZONE = Zone.fromFile(
  '.',
  path.join(__dirname, 'root.zone.signed')
);
const WEAKKEYTLD_ZONE = Zone.fromFile(
  'weakkeytld.',
  path.join(__dirname, 'weakkeytld.zone.signed')
);

class FakeStub {
  open() {}
  close() {}
  lookup (name, type) {
    const msg = new Message();

    msg.answer = ROOT_ZONE.get(name, type);
    if (!msg.answer.length)
        msg.answer = WEAKKEYTLD_ZONE.get(name, type);

    return msg;
  }
}

const fakeOwnership = new Ownership();
fakeOwnership.anchors = [KSK];
fakeOwnership.rootAnchors = fakeOwnership.anchors;
fakeOwnership.Resolver = FakeStub;

exports.fakeOwnership = fakeOwnership;
exports.FakeStub = FakeStub;
