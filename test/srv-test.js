/* eslint-env mocha */
/* eslint prefer-arrow-callback: "off" */

'use strict';

const assert = require('bsert');
const srv = require('../lib/srv');
const wire = require('../lib/wire');

// $ dig.js _xmpp-server._tcp.gmail.com SRV
const xmpp = `
_xmpp-server._tcp.gmail.com. 900 IN SRV 20 0 5269 alt1.xmpp-server.l.google.com.
_xmpp-server._tcp.gmail.com. 900 IN SRV 20 0 5269 alt3.xmpp-server.l.google.com.
_xmpp-server._tcp.gmail.com. 900 IN SRV 20 0 5269 alt2.xmpp-server.l.google.com.
_xmpp-server._tcp.gmail.com. 900 IN SRV 5 0 5269 xmpp-server.l.google.com.
_xmpp-server._tcp.gmail.com. 900 IN SRV 20 0 5269 alt4.xmpp-server.l.google.com.
`;

describe('SRV', function() {
  it('should serialize name', () => {
    const name = srv.encodeName('example.com', 'tcp', 'smtp');

    assert.strictEqual(name, '_smtp._tcp.example.com.');
    assert(srv.isName(name));
    assert(!srv.isName('example.com.'));

    const data = srv.decodeName(name);

    assert.strictEqual(data.name, 'example.com.');
    assert.strictEqual(data.protocol, 'tcp');
    assert.strictEqual(data.service, 'smtp');
  });

  it('should parse SRV records', () => {
    wire.fromZone(xmpp);
  });
});
