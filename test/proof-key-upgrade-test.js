/* eslint-env mocha */
/* eslint prefer-arrow-callback: "off" */

'use strict';

const assert = require('bsert');
const path = require('path');
const {fakeOwnership, FakeStub} = require('./prove-util/fakeownership');
const dnssec = require('../lib/dnssec');
const {types, keyFlags} = require('../lib/wire');

describe('Ownership Proof Key Upgrade', function () {
  const ownership = fakeOwnership;

  it('should fail by default to generate insecure proof', async () => {
    // They don't even count as actual RRSIGs
    await assert.rejects(
      ownership._prove(new FakeStub(), 'weakkeytld.', false),
      {message: 'No RRSIG(TXT) records for weakkeytld.'}
    );

    // Sanity check
    const res = new FakeStub().lookup('weakkeytld.', types.TXT);
    assert(res.answer[1].type === types.RRSIG);
    assert(ownership.isSHA1(res.answer[1].data.algorithm));
  });

  it('should generate insecure proof when forced', async () => {
    try {
      ownership.secure = false;
      const fakeStub = new FakeStub();

      const proof = await ownership._prove(
        fakeStub,
        'weakkeytld.',
        false
      );
      assert(ownership.isSane(proof));
      assert(ownership.verifySignatures(proof));

      // Sanity checks
      const claim = proof.zones[proof.zones.length - 1].claim;
      const claimSig = claim[claim.length - 1];
      // Signed with SHA1
      assert(ownership.isSHA1(claimSig.data.algorithm));
      // Signed with ZSK, not KSK
      const keyTag = claimSig.data.keyTag;
      const dnskeys = await fakeStub.lookup('weakkeytld.', types.DNSKEY);
      let foundKey = false;
      for (const rr of dnskeys.answer) {
        if (rr.type === types.DNSKEY && rr.data.keyTag() === keyTag) {
          foundKey = true;
          assert(rr.data.flags & keyFlags.ZONE);
          assert(!(rr.data.flags & keyFlags.SEP));
        }
      }
      assert(foundKey);
    } finally {
      ownership.secure = true;
    }
  });

  it('should upgrade weak key algorithm', async () => {
    let proof, target;
    try {
      ownership.secure = false; // needed to get proof template
      proof = await ownership._prove(new FakeStub(), 'weakkeytld.', true);
      target = proof.zones[1];
      const key = target.keys[1];
      const txtRR = proof.zones[1].claim[0];

      assert(key.type === types.DNSKEY);
      assert(key.data.flags & keyFlags.SEP);
      assert(txtRR.type === types.TXT);

      // Kweakkeytld.+005+08014.key
      const priv = await dnssec.readPrivateAsync(
        path.join(__dirname, 'prove-util'),
        key
      );

      // Here's the sneaky magic: create a duplicate key with better algorithm.
      const key256 = dnssec.upgradeDNSKEY(key);

      // Sign DNSKEY RRset now including both old and new keys.
      const keySig = dnssec.sign(key256, priv, [key256, key], 24 * 60 * 60);
      target.keys[0] = key;
      target.keys[1] = key256;
      target.keys[2] = keySig;

      // Now sign the claim TXT with the new key
      const txtSig = dnssec.sign(key256, priv, [txtRR], 24 * 60 * 60);
      target.claim[1] = txtSig;
    } finally {
      ownership.secure = true; // default, and required by HNS consensus rules
    }

    assert(ownership.isSane(proof));
    assert(ownership.verifySignatures(proof));

    // Sanity check
    assert(target.claim[1].type === types.RRSIG);
    assert(!ownership.isSHA1(target.claim[1].data.algorithm));
  });
});
