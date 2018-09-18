/* eslint-env mocha */
/* eslint prefer-arrow-callback: "off" */

'use strict';

const assert = require('./util/assert');
const Ownership = require('../lib/ownership');
const util = require('../lib/util');
const vectors = require('./data/ownership.json');
const {OwnershipProof} = Ownership;

function verifyProof(name, ownership, proof, weak) {
  assert(ownership.isSane(proof), `${name}: invalid-sanity`);
  assert(ownership.verifyTimes(proof, util.now()), `${name}: invalid-times`);
  assert(ownership.verifySignatures(proof), `${name}: invalid-signatures`);
  assert.strictEqual(ownership.isWeak(proof), weak, `${name}: invalid-weak`);
  assert(ownership.isKSK2010(proof), `${name}: invalid-ksk`);
}

describe('Ownership', function() {
  this.timeout(10000);

  for (const vector of vectors) {
    const {name, secure, weak} = vector;
    const proof = OwnershipProof.fromHex(vector.proof);

    it(`should test ownership for ${name} (s=${secure}, w=${weak})`, () => {
      const ownership = new Ownership();

      ownership.secure = secure;

      verifyProof(name, ownership, proof, weak);

      const raw = proof.toHex();
      const unraw = OwnershipProof.fromHex(raw);

      assert.strictEqual(raw, unraw.toHex());

      verifyProof(name, ownership, unraw, weak);

      const txt = proof.toString();
      const untxt = OwnershipProof.fromString(txt);

      assert.strictEqual(raw, untxt.toHex());

      return proof;
    });
  }
});
