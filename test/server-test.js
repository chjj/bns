/* eslint-env mocha */
/* eslint prefer-arrow-callback: "off" */

'use strict';

const assert = require('./util/assert');
const util = require('../lib/util');
const wire = require('../lib/wire');
const Server = require('../lib/server/dns');
const api = require('../lib/dns');
const {types} = wire;

// Mimic the records in `stub-test.js`.
const records = {
  [types.ANY]: [
    'google.com. 300 IN A 216.58.195.78',
    'google.com. 300 IN AAAA 2607:f8b0:4005:807::200e',
    'google.com. 3600 IN TXT "v=spf1 include:_spf.google.com ~all"',
    'google.com. 600 IN MX 10 aspmx.l.google.com.',
    'google.com. 600 IN MX 30 alt2.aspmx.l.google.com.',
    'google.com. 86400 IN CAA 0 issue "pki.goog"',
    'google.com. 60 IN SOA ns1.google.com. dns-admin.google.com.'
      + ' 213603989 900 900 1800 60',
    'google.com. 3600 IN TXT'
      + ' "facebook-domain-verification=22rm551cu4k0ab0bxsw536tlds4h95"',
    'google.com. 600 IN MX 50 alt4.aspmx.l.google.com.',
    'google.com. 345600 IN NS ns2.google.com.',
    'google.com. 345600 IN NS ns4.google.com.',
    'google.com. 345600 IN NS ns3.google.com.',
    'google.com. 600 IN MX 40 alt3.aspmx.l.google.com.',
    'google.com. 300 IN TXT "docusign=05958488-4752-4ef2-95eb-aa7ba8a3bd0e"',
    'google.com. 345600 IN NS ns1.google.com.',
    'google.com. 600 IN MX 20 alt1.aspmx.l.google.com.'
  ],
  [types.A]: [
    'icanhazip.com. 300 IN A 147.75.40.2'
  ],
  [types.AAAA]: [
    'icanhazip.com. 300 IN AAAA 2604:1380:1000:af00::1',
    'icanhazip.com. 300 IN AAAA 2604:1380:3000:3b00::1',
    'icanhazip.com. 300 IN AAAA 2604:1380:1:cd00::1'
  ],
  [types.CNAME]: [
    'mail.google.com. 604800 IN CNAME googlemail.l.google.com.'
  ],
  [types.MX]: [
    'google.com. 600 IN MX 40 alt3.aspmx.l.google.com.',
    'google.com. 600 IN MX 20 alt1.aspmx.l.google.com.',
    'google.com. 600 IN MX 50 alt4.aspmx.l.google.com.',
    'google.com. 600 IN MX 30 alt2.aspmx.l.google.com.',
    'google.com. 600 IN MX 10 aspmx.l.google.com.'
  ],
  [types.NAPTR]: [
    'apple.com. 86400 IN NAPTR 50 50 "se" "SIPS+D2T" "" _sips._tcp.apple.com.',
    'apple.com. 86400 IN NAPTR 90 50 "se" "SIP+D2T" "" _sip._tcp.apple.com.',
    'apple.com. 86400 IN NAPTR 100 50 "se" "SIP+D2U" "" _sip._udp.apple.com.'
  ],
  [types.PTR]: [
    '46.0.217.172.in-addr.arpa. 86400 IN PTR lga15s43-in-f46.1e100.net.',
    '46.0.217.172.in-addr.arpa. 86400 IN PTR sfo07s26-in-f14.1e100.net.',
    '46.0.217.172.in-addr.arpa. 86400 IN PTR lga15s43-in-f14.1e100.net.',
    '46.0.217.172.in-addr.arpa. 86400 IN PTR lga15s43-in-f46.1e100.net.',
    '46.0.217.172.in-addr.arpa. 86400 IN PTR sfo07s26-in-f14.1e100.net.',
    '46.0.217.172.in-addr.arpa. 86400 IN PTR lga15s43-in-f14.1e100.net.'
  ],
  [types.SOA]: [
    'google.com. 60 IN SOA ns1.google.com. dns-admin.google.com.'
      + ' 213603989 900 900 1800 60'
  ],
  [types.SRV]: [
    '_xmpp-server._tcp.gmail.com. 900 IN SRV 20 0 5269'
      + ' alt4.xmpp-server.l.google.com.',
    '_xmpp-server._tcp.gmail.com. 900 IN SRV 20 0 5269'
      + ' alt3.xmpp-server.l.google.com.',
    '_xmpp-server._tcp.gmail.com. 900 IN SRV 5 0 5269'
      + ' xmpp-server.l.google.com.',
    '_xmpp-server._tcp.gmail.com. 900 IN SRV 20 0 5269'
      + ' alt1.xmpp-server.l.google.com.',
    '_xmpp-server._tcp.gmail.com. 900 IN SRV 20 0 5269'
      + ' alt2.xmpp-server.l.google.com.'
  ],
  [types.TXT]: [
    'google.com. 3600 IN TXT'
      + ' "facebook-domain-verification=22rm551cu4k0ab0bxsw536tlds4h95"',
    'google.com. 300 IN TXT "docusign=05958488-4752-4ef2-95eb-aa7ba8a3bd0e"',
    'google.com. 3600 IN TXT "v=spf1 include:_spf.google.com ~all"'
  ]
};

function getAnswer(type) {
  const txt = records[type];

  if (!Array.isArray(txt))
    return null;

  return wire.fromZone(txt.join('\n'));
}

describe('Server', function() {
  let server;
  let dns;

  it('should listen on port 5300', async () => {
    server = new Server({
      tcp: true,
      maxConnections: 20,
      edns: true,
      ednsSize: 4096,
      dnssec: true
    });

    server.on('query', (req, res, rinfo) => {
      const [qs] = req.question;
      const answer = getAnswer(qs.type);

      if (!answer || !util.equal(qs.name, answer[0].name)) {
        res.code = wire.codes.NXDOMAIN;
        res.send();
        return;
      }

      res.answer = answer;
      res.send();
    });

    await server.bind(5300, '127.0.0.1');
  });

  it('should instantiate resolver', async () => {
    dns = new api.Resolver();

    dns.setServers(['127.0.0.1:5300']);
  });

  it('should respond to A request', async () => {
    assert.deepStrictEqual(await dns.lookup('icanhazip.com'), {
      address: '147.75.40.2',
      family: 4
    });
  });

  it('should respond to PTR request', async () => {
    assert.deepStrictEqual(await dns.lookupService('172.217.0.46', 80), {
      hostname: 'lga15s43-in-f46.1e100.net',
      service: 'http'
    });
  });

  it('should respond to ANY request', async () => {
    assert.deepStrictEqual(await dns.resolveAny('google.com'), [
      { address: '216.58.195.78', ttl: 300, type: 'A' },
      { address: '2607:f8b0:4005:807::200e', ttl: 300, type: 'AAAA' },
      { entries: ['v=spf1 include:_spf.google.com ~all'], type: 'TXT' },
      { exchange: 'aspmx.l.google.com', priority: 10, type: 'MX' },
      { exchange: 'alt2.aspmx.l.google.com', priority: 30, type: 'MX' },
      {
        nsname: 'ns1.google.com',
        hostmaster: 'dns-admin.google.com',
        serial: 213603989,
        refresh: 900,
        retry: 900,
        expire: 1800,
        minttl: 60,
        type: 'SOA'
      },
      {
        entries: [
          'facebook-domain-verification=22rm551cu4k0ab0bxsw536tlds4h95'
        ],
        type: 'TXT'
      },
      { exchange: 'alt4.aspmx.l.google.com', priority: 50, type: 'MX' },
      { value: 'ns2.google.com', type: 'NS' },
      { value: 'ns4.google.com', type: 'NS' },
      { value: 'ns3.google.com', type: 'NS' },
      { exchange: 'alt3.aspmx.l.google.com', priority: 40, type: 'MX' },
      {
        entries: ['docusign=05958488-4752-4ef2-95eb-aa7ba8a3bd0e'],
        type: 'TXT'
      },
      { value: 'ns1.google.com', type: 'NS' },
      { exchange: 'alt1.aspmx.l.google.com', priority: 20, type: 'MX' }
    ]);
  });

  it('should respond to A request', async () => {
    assert.deepStrictEqual(await dns.resolve4('icanhazip.com'), [
      '147.75.40.2'
    ]);
  });

  it('should respond to AAAA request', async () => {
    assert.deepStrictEqual(await dns.resolve6('icanhazip.com'), [
      '2604:1380:1000:af00::1',
      '2604:1380:3000:3b00::1',
      '2604:1380:1:cd00::1'
    ]);
  });

  it('should respond to CNAME request', async () => {
    assert.deepStrictEqual(await dns.resolveCname('mail.google.com'), [
      'googlemail.l.google.com'
    ]);
  });

  it('should respond to MX request', async () => {
    assert.deepStrictEqual(await dns.resolveMx('google.com'), [
      { exchange: 'alt3.aspmx.l.google.com', priority: 40 },
      { exchange: 'alt1.aspmx.l.google.com', priority: 20 },
      { exchange: 'alt4.aspmx.l.google.com', priority: 50 },
      { exchange: 'alt2.aspmx.l.google.com', priority: 30 },
      { exchange: 'aspmx.l.google.com', priority: 10 }
    ]);
  });

  it('should respond to NAPTR request', async () => {
    assert.deepStrictEqual(await dns.resolveNaptr('apple.com'), [
      {
        flags: 'se',
        service: 'SIPS+D2T',
        regexp: '',
        replacement: '_sips._tcp.apple.com',
        order: 50,
        preference: 50
      },
      {
        flags: 'se',
        service: 'SIP+D2T',
        regexp: '',
        replacement: '_sip._tcp.apple.com',
        order: 90,
        preference: 50
      },
      {
        flags: 'se',
        service: 'SIP+D2U',
        regexp: '',
        replacement: '_sip._udp.apple.com',
        order: 100,
        preference: 50
      }
    ]);
  });

  it('should respond to PTR request', async () => {
    assert.deepStrictEqual(await dns.resolvePtr('46.0.217.172.in-addr.arpa.'), [
      'lga15s43-in-f46.1e100.net',
      'sfo07s26-in-f14.1e100.net',
      'lga15s43-in-f14.1e100.net',
      'lga15s43-in-f46.1e100.net',
      'sfo07s26-in-f14.1e100.net',
      'lga15s43-in-f14.1e100.net'
    ]);
  });

  it('should respond to SOA request', async () => {
    assert.deepStrictEqual(await dns.resolveSoa('google.com'), {
      nsname: 'ns1.google.com',
      hostmaster: 'dns-admin.google.com',
      serial: 213603989,
      refresh: 900,
      retry: 900,
      expire: 1800,
      minttl: 60
    });
  });

  it('should respond to SRV request', async () => {
    assert.deepStrictEqual(
      await dns.resolveSrv('_xmpp-server._tcp.gmail.com'),
      [
        { name: 'alt4.xmpp-server.l.google.com',
          port: 5269,
          priority: 20,
          weight: 0 },
        { name: 'alt3.xmpp-server.l.google.com',
          port: 5269,
          priority: 20,
          weight: 0 },
        { name: 'xmpp-server.l.google.com',
          port: 5269,
          priority: 5,
          weight: 0 },
        { name: 'alt1.xmpp-server.l.google.com',
          port: 5269,
          priority: 20,
          weight: 0 },
        { name: 'alt2.xmpp-server.l.google.com',
          port: 5269,
          priority: 20,
          weight: 0 }
      ]
    );
  });

  it('should respond to TXT request', async () => {
    assert.deepStrictEqual(await dns.resolveTxt('google.com'), [
      ['facebook-domain-verification=22rm551cu4k0ab0bxsw536tlds4h95'],
      ['docusign=05958488-4752-4ef2-95eb-aa7ba8a3bd0e'],
      ['v=spf1 include:_spf.google.com ~all']
    ]);
  });

  it('should respond to PTR request', async () => {
    assert.deepStrictEqual(await dns.reverse('172.217.0.46'), [
      'lga15s43-in-f46.1e100.net',
      'sfo07s26-in-f14.1e100.net',
      'lga15s43-in-f14.1e100.net',
      'lga15s43-in-f46.1e100.net',
      'sfo07s26-in-f14.1e100.net',
      'lga15s43-in-f14.1e100.net'
    ]);
  });

  it('should close server', async () => {
    await server.close();
  });
});
