/* eslint-env mocha */
/* eslint prefer-arrow-callback: "off" */

'use strict';

const assert = require('./util/assert');
const dns = require('dns').promises;
const api = require('../lib/dns');
const util = require('../lib/util');

const servers = [
  '8.8.8.8',
  '8.8.4.4'
];

function sort(items) {
  if (!Array.isArray(items))
    return items;

  return items.slice().sort((a, b) => {
    const x = JSON.stringify(a);
    const y = JSON.stringify(b);
    return util.compare(x, y);
  });
}

describe('Stub', function() {
  const bns = new api.Resolver();

  it('should resolve', async () => {
    dns.setServers(servers);
    bns.setServers(servers);

    const test = async (method, name, ...args) => {
      const x = await dns[method](name, ...args);
      const y = await bns[method](name, ...args);
      assert.deepStrictEqual(sort(x), sort(y), `dns.${method}('${name}')`);
    };

    await test('lookup', 'icanhazip.com');
    // await test('lookupService', '172.217.0.46', 80);
    // await test('resolveAny', 'google.com');
    await test('resolve4', 'icanhazip.com');
    await test('resolve6', 'icanhazip.com');
    await test('resolveCname', 'mail.google.com');
    await test('resolveMx', 'google.com');
    await test('resolveNaptr', 'apple.com');
    // await test('resolvePtr', '46.0.217.172.in-addr.arpa.');
    // await test('resolveSoa', 'google.com');
    await test('resolveSrv', '_xmpp-server._tcp.gmail.com');
    await test('resolveTxt', 'google.com');
    // await test('reverse', '172.217.0.46');
  });
});
