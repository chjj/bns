/* eslint-env mocha */
/* eslint prefer-arrow-callback: "off" */

'use strict';

const assert = require('./util/assert');
const Authority = require('../lib/authority');

describe('Authority', function() {
  it('should add servers', () => {
    const auth = new Authority('com.', 'ns1.com.');
    assert.strictEqual(auth.servers.length, 0);

    auth.add('127.0.0.1', 53);

    assert.strictEqual(auth.servers.length, 1);
    assert.strictEqual(auth.servers[0].host, '127.0.0.1');
    assert.strictEqual(auth.servers[0].port, 53);

    assert.deepStrictEqual(auth.clone(), auth);
  });
});
