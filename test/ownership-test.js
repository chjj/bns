/* eslint-env mocha */
/* eslint prefer-arrow-callback: "off" */

'use strict';

const assert = require('./util/assert');
const Ownership = require('../lib/ownership');
const util = require('../lib/util');
const Resolver = require('../lib/resolver/stub');

async function testOwnership(name, secure) {
  const ownership = new Ownership(Resolver, secure);
  const proof = await ownership.prove(name);

  assert(ownership.verifySanity(proof), 'invalid-sanity');
  assert(ownership.verifyTimes(proof, util.now()), 'invalid-times');
  assert(ownership.verifySignatures(proof), 'invalid-signatures');

  return proof;
}

describe('Ownership', function() {
  it('should verify proof for ietf.org', async () => {
    const proof1 = await testOwnership('ietf.org.', false);
    assert(proof1);
  });

  it('should verify proof for nlnetlabs.nl', async () => {
    const proof1 = await testOwnership('nlnetlabs.nl.', false);
    assert(proof1);
    const proof2 = await testOwnership('nlnetlabs.nl.', true);
    assert(proof2);
  });

  it('should verify proof for nlnet.nl', async () => {
    const proof1 = await testOwnership('nlnet.nl.', false);
    assert(proof1);
    const proof2 = await testOwnership('nlnet.nl.', true);
    assert(proof2);
  });
});
