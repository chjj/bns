/* eslint-env mocha */
/* eslint prefer-arrow-callback: "off" */

'use strict';

const assert = require('./util/assert');
const Ownership = require('../lib/ownership');
const util = require('../lib/util');
const Resolver = require('../lib/resolver/stub');
const {OwnershipProof} = Ownership;

function verifyProof(name, ownership, proof, weak) {
  assert(ownership.isSane(proof), `${name}: invalid-sanity`);
  assert(ownership.verifyTimes(proof, util.now()), `${name}: invalid-times`);
  assert(ownership.verifySignatures(proof), `${name}: invalid-signatures`);
  assert.strictEqual(ownership.isWeak(proof), weak, `${name}: invalid-weak`);
  assert(ownership.isKSK2010(proof), `${name}: invalid-ksk`);
}

async function testOwnership(name, secure, weak) {
  const ownership = new Ownership();

  ownership.Resolver = Resolver;
  ownership.secure = secure;

  const proof = await ownership.prove(name);

  verifyProof(name, ownership, proof, weak);

  const raw = proof.toHex();
  const unraw = OwnershipProof.fromHex(raw);

  assert.strictEqual(raw, unraw.toHex());

  verifyProof(name, ownership, unraw, weak);

  const txt = proof.toString();
  const untxt = OwnershipProof.fromString(txt);

  assert.strictEqual(raw, untxt.toHex());

  return proof;
}

const provableNames = [
  ['cloudflare.com.', true, true],
  // ['dnssec-name-and-shame.com.', true, true], // No TXT records
  // ['getdnsapi.net.', true, true], // No TXT records
  ['nlnetlabs.nl.', true, true],
  ['nlnet.nl.', true, true],
  ['verisigninc.com.', true, true],
  ['iis.se.', false, true],
  ['kirei.se.', true, false],
  ['opendnssec.org.', false, true],
  ['ietf.org.', false, true],
  ['iana.org.', false, true]
  // ['internetsociety.org.', false, true] // 33 bit exponent
];

describe('Ownership', function() {
  this.timeout(10000);

  for (const [name, secure, weak] of provableNames) {
    it(`should verify proof for ${util.trimFQDN(name)}`, async () => {
      const proof1 = await testOwnership(name, secure, weak);
      assert(proof1);
      if (secure) {
        const proof2 = await testOwnership(name, false, weak);
        assert(proof2);
      }
    });
  }
});
