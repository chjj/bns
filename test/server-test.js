/* eslint-env mocha */
/* eslint prefer-arrow-callback: "off" */

'use strict';

const net = require('net');
const assert = require('bsert');
const Path = require('path');
const fs = require('bfile');
const util = require('../lib/util');
const wire = require('../lib/wire');
const Server = require('../lib/server/dns');
const api = require('../lib/dns');
const StubResolver = require('../lib/resolver/stub');
const RecursiveResolver = require('../lib/resolver/recursive');
const UnboundResolver = require('../lib/resolver/unbound');
const RootResolver = require('../lib/resolver/root');
const AuthServer = require('../lib/server/auth');
const RecursiveServer = require('../lib/server/recursive');
const {types, codes, Record, KSK_2010} = wire;

const ROOT_ZONE = Path.resolve(__dirname, 'data', 'root.zone');
const COM_RESPONSE = Path.resolve(__dirname, 'data', 'com-response.zone');
const COM_GLUE = Path.resolve(__dirname, 'data', 'com-glue.zone');
const NX_RESPONSE = Path.resolve(__dirname, 'data', 'nx-response.zone');

const serverRecords = require('./data/server-records.json');
const comResponse = fs.readFileSync(COM_RESPONSE, 'utf8');
const comGlue = fs.readFileSync(COM_GLUE, 'utf8');
const nxResponse = fs.readFileSync(NX_RESPONSE, 'utf8');

if (process.browser)
  return;

describe('Server', function() {
  this.timeout(20000);

  let server = null;
  let dns = null;
  let authServer = null;
  let recServer = null;
  let authQueries = 0;
  let recQueries = 0;
  let inet6 = true;

  before(() => {
    // Test platform for ipv6 support.
    // A.ROOT-SERVERS.NET.
    const testIPv6 = net.connect({host: '2001:503:ba3e::2:30', port: 53})
      .on('error', (e) => {
        assert(e.code === 'EHOSTUNREACH' || e.code === 'ENETUNREACH');
        inet6 = false;
        testIPv6.destroy();
      });

    // IPv4 should always be supported.
    // A.ROOT-SERVERS.NET.
    const testIPv4 = net.connect({host: '198.41.0.4', port: 53})
      .on('connect', () => {
        testIPv4.destroy();
      });
  });

  it('should listen on port 5300', async () => {
    server = new Server({
      tcp: true,
      maxConnections: 20,
      edns: true,
      dnssec: true
    });

    server.on('error', (err) => {
      throw err;
    });

    const getAnswer = (type) => {
      const txt = serverRecords[wire.typeToString(type)];

      if (!Array.isArray(txt))
        return null;

      return wire.fromZone(txt.join('\n'));
    };

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

  it('should open authoritative server', async () => {
    authServer = new AuthServer({
      tcp: true,
      edns: true,
      dnssec: true
    });

    authServer.on('error', (err) => {
      throw err;
    });

    authServer.on('query', () => {
      authQueries += 1;
    });

    authServer.setOrigin('.');
    authServer.setFile(ROOT_ZONE);

    await authServer.bind(5301, '127.0.0.1');
  });

  it('should open recursive server', async () => {
    recServer = new RecursiveServer({
      tcp: true,
      inet6,
      edns: true,
      dnssec: true
    });

    recServer.on('error', (err) => {
      throw err;
    });

    recServer.on('query', () => {
      recQueries += 1;
    });

    recServer.resolver.setStub(
      '127.0.0.1',
      5301,
      Record.fromString(KSK_2010)
    );

    await recServer.bind(5302, '127.0.0.1');
  });

  it('should query authoritative server (stub)', async () => {
    const stub = new StubResolver({
      rd: false,
      cd: false,
      edns: true,
      dnssec: true,
      hosts: [
        ['localhost.', '127.0.0.1'],
        ['localhost.', '::1']
      ],
      servers: ['127.0.0.1:5301']
    });

    stub.on('error', (err) => {
      throw err;
    });

    await stub.open();

    {
      const msg = await stub.lookup('com.', types.NS);
      assert(msg.code === codes.NOERROR);
      assert(!msg.aa);

      const expect = wire.fromZone(comResponse);
      assert.deepStrictEqual(msg.authority, expect);

      const glue = wire.fromZone(comGlue);
      assert.deepStrictEqual(msg.additional, glue);
    }

    {
      const msg = await stub.lookup('idontexist.', types.A);
      assert(!msg.aa);
      assert(msg.code === codes.NXDOMAIN);
      assert(msg.answer.length === 0);

      const expect = wire.fromZone(nxResponse);
      assert.deepStrictEqual(msg.authority, expect);
    }

    await stub.close();
  });

  it('should query recursive server (stub)', async () => {
    const stub = new StubResolver({
      rd: true,
      cd: false,
      edns: true,
      dnssec: true,
      hosts: [
        ['localhost.', '127.0.0.1'],
        ['localhost.', '::1']
      ],
      servers: ['127.0.0.1:5302']
    });

    stub.on('error', (err) => {
      throw err;
    });

    await stub.open();

    const msg = await stub.lookup('google.com.', types.A);
    assert(msg.code === codes.NOERROR);
    assert(msg.answer.length > 0);
    assert(msg.answer[0].name === 'google.com.');
    assert(msg.answer[0].type === types.A);

    await stub.close();
  });

  it('should do a recursive resolution', async () => {
    const res = new RecursiveResolver({
      tcp: true,
      inet6,
      edns: true,
      dnssec: true
    });

    res.setStub('127.0.0.1', 5301, Record.fromString(KSK_2010));

    res.on('error', (err) => {
      throw err;
    });

    await res.open();

    const msg = await res.lookup('google.com.', types.A);
    assert(msg.code === codes.NOERROR);
    assert(msg.answer.length > 0);
    assert(msg.answer[0].name === 'google.com.');
    assert(msg.answer[0].type === types.A);

    await res.close();
  });

  it('should do a recursive resolution (unbound)', async () => {
    const res = new UnboundResolver({
      tcp: true,
      inet6,
      edns: true,
      dnssec: true
    });

    res.setStub('127.0.0.1', 5301, Record.fromString(KSK_2010));

    res.on('error', (err) => {
      throw err;
    });

    await res.open();

    const msg = await res.lookup('google.com.', types.A);
    assert(msg.code === codes.NOERROR);
    assert(msg.answer.length > 0);
    assert(msg.answer[0].name === 'google.com.');
    assert(msg.answer[0].type === types.A);

    await res.close();
  });

  it('should do a root resolution', async () => {
    const res = new RootResolver({
      tcp: true,
      inet6,
      edns: true,
      dnssec: true
    });

    res.on('error', (err) => {
      throw err;
    });

    res.servers = [{
      host: '127.0.0.1',
      port: 5301
    }];

    await res.open();

    util.fakeTime('2018-08-05:00:00.000Z');

    const msg = await res.lookup('com.');
    assert(msg.code === codes.NOERROR);
    assert(!msg.aa);
    assert(msg.ad);

    const expect = wire.fromZone(comResponse);
    expect.pop(); // pop signature
    assert.deepStrictEqual(msg.authority, expect);

    const glue = wire.fromZone(comGlue);
    assert.deepStrictEqual(msg.additional, glue);

    util.fakeTime();

    await res.close();
  });

  it('should have total requests', () => {
    assert.strictEqual(authQueries, 16);
    assert.strictEqual(recQueries, 1);
  });

  it('should close servers', async () => {
    await recServer.close();
    await authServer.close();
  });
});
