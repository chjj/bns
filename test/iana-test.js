/* eslint-env mocha */
/* eslint prefer-arrow-callback: "off" */

'use strict';

const assert = require('bsert');
const iana = require('../lib/internal/iana');

describe('IANA', function() {
  it('should have services and ports', () => {
    assert.strictEqual(iana.getPort('ssh'), 22);
    assert.strictEqual(iana.getService(22), 'ssh');
    assert.strictEqual(iana.protocolToString(iana.protocols.ICMP), 'ICMP');
    assert.strictEqual(iana.stringToProtocol('ICMP'), iana.protocols.ICMP);
  });
});
