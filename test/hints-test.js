/* eslint-env mocha */
/* eslint prefer-arrow-callback: "off" */

'use strict';

const assert = require('./util/assert');
const Authority = require('../lib/authority');
const Hints = require('../lib/hints');

describe('Hints', function() {
  it('should add servers', () => {
    const hints = new Hints();

    hints.addServer('a.root-servers.net.', '127.0.0.1');
    hints.addServer('a.root-servers.net.', '::1');

    const auth = hints.getAuthority();
    assert(auth instanceof Authority);
    assert.strictEqual(auth.servers.length, 1);
    assert.strictEqual(auth.servers[0].host, '127.0.0.1');
    assert.strictEqual(auth.servers[0].port, 53);

    const auth2 = hints.getAuthority(true);
    assert(auth2 instanceof Authority);
    assert.strictEqual(auth.servers.length, 1);
    assert.strictEqual(auth2.servers[0].host, '::1');
    assert.strictEqual(auth2.servers[0].port, 53);
  });

  it('should add default', () => {
    const hints = new Hints();
    hints.setDefault();

    const auth = hints.getAuthority();
    assert.strictEqual(auth.servers.length, 13);

    const str = hints.toString();
    const hints2 = Hints.fromString(str);

    assert.deepStrictEqual(hints2, hints);
  });
});
