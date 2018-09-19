/* eslint-env mocha */
/* eslint prefer-arrow-callback: "off" */

'use strict';

const assert = require('./util/assert');
const iana = require('../lib/iana');

describe('IANA', function() {
  it('should have services and ports', () => {
    assert.strictEqual(iana.getPort('ssh'), 22);
    assert.strictEqual(iana.getService(22), 'ssh');
    assert.strictEqual(iana.protocolToString(iana.protocols.ICMP), 'ICMP');
    assert.strictEqual(iana.stringToProtocol('ICMP'), iana.protocols.ICMP);
  });
});
