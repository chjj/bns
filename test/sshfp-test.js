/* eslint-env mocha */
/* eslint prefer-arrow-callback: "off" */

'use strict';

const assert = require('./util/assert');
const sshfp = require('../lib/sshfp');
const {algs, hashes} = sshfp;

describe('SSHFP', function() {
  it('should create SSHFP and verify', () => {
    const key = Buffer.alloc(32, 0x01);
    const rr = sshfp.create(key, 'example.com.', algs.ED25519, hashes.SHA256);

    assert(sshfp.verify(rr, key));

    key[0] ^= 1;

    assert(!sshfp.verify(rr, key));
  });
});
