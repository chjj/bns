/* eslint-env mocha */
/* eslint prefer-arrow-callback: "off" */

'use strict';

const assert = require('bsert');
const RecursiveResolver = require('../lib/resolver/recursive');
const UnboundResolver = require('../lib/resolver/unbound');
const rdns = require('../lib/rdns');
const udns = require('../lib/udns');
const {types, codes} = require('../lib/wire');

const dnssecNames = [
  'cloudflare.com',
  'dnssec-name-and-shame.com',
  'nlnetlabs.nl',
  'nlnet.nl',
  'labs.verisigninc.com',
  'iis.se',
  'www.kirei.se',
  'www.opendnssec.org',
  'www.ietf.org',
  'www.iana.org',
  'internetsociety.org',
  'ed25519.nl',
  'ed448.nl'
];

const nxNames = [
  'ww.dnssec-name-and-shame.com',
  'ww.nlnet.nl',
  'ww.opendnssec.org'
];

const nodataNames = [
  'dnssec-name-and-shame.com',
  'nlnet.nl',
  'www.opendnssec.org'
];

const noDnssecNames = [
  'google.com'
];

const badDnssecNames = [
  'www.dnssec-failed.org',
  'rhybar.cz'
];

const noNxNames = [
  'nxdomain.google.com'
];

const noNodataNames = [
  'google.com'
];

if (process.browser)
  return;

function checkUBversion(string) {
  const digits = string.split('.');

  // Require support for ED448, at least version 1.8.x
  if (parseInt(digits[0]) > 1)
    return true;

  if (parseInt(digits[0]) < 1)
    return false;

  if (parseInt(digits[1]) < 8)
    return false;

  return true;
}

describe('Recursive', function() {
  this.timeout(20000);

  it(`should return the version of libunbound: ${udns.version}`, () => {
    ;
  });

  for (const Resolver of [RecursiveResolver, UnboundResolver]) {
    it('should do a recursive resolution', async () => {
      const res = new Resolver({
        tcp: true,
        inet6: false,
        edns: true,
        dnssec: true
      });

      res.hints.setDefault();

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
  }

  for (const dns of [rdns, udns]) {
    describe(`${dns === rdns ? 'JavaScript' : 'Unbound'}`, function () {
      for (const name of dnssecNames) {
        if (name === 'ed25519.nl' || name === 'ed448.nl') {
          if (dns === udns && !checkUBversion(udns.version))
            continue;
        }

        it(`should validate trust chain for ${name}`, async () => {
          const res = await dns.resolveRaw(name, types.A);
          assert.strictEqual(res.code, codes.NOERROR);
          assert(res.answer.length > 0);
          assert(res.ad);
        });
      }

      for (const name of nxNames) {
        it(`should validate NX proof for ${name}`, async () => {
          const res = await dns.resolveRaw(name, types.A);
          assert.strictEqual(res.code, codes.NXDOMAIN);
          assert(res.answer.length === 0);
          assert(res.ad);
        });
      }

      for (const name of nodataNames) {
        it(`should validate NODATA proof for ${name}`, async () => {
          const res = await dns.resolveRaw(name, types.WKS);
          assert.strictEqual(res.code, codes.NOERROR);
          assert(res.answer.length === 0);
          assert(res.ad);
        });
      }

      for (const name of noDnssecNames) {
        it(`should fail to validate trust chain for ${name}`, async () => {
          const res = await dns.resolveRaw(name, types.A);
          assert.strictEqual(res.code, codes.NOERROR);
          assert(res.answer.length > 0);
          assert(!res.ad);
        });
      }

      for (const name of noNxNames) {
        it(`should fail to validate NX proof for ${name}`, async () => {
          const res = await dns.resolveRaw(name, types.A);
          assert.strictEqual(res.code, codes.NXDOMAIN);
          assert(res.answer.length === 0);
          assert(!res.ad);
        });
      }

      for (const name of noNodataNames) {
        it(`should fail to validate NODATA proof for ${name}`, async () => {
          const res = await dns.resolveRaw(name, types.WKS);
          assert.strictEqual(res.code, codes.NOERROR);
          assert(res.answer.length === 0);
          assert(!res.ad);
        });
      }

      for (const name of badDnssecNames) {
        it(`should fail to validate bad signature for ${name}`, async () => {
          const res = await dns.resolveRaw(name, types.A);
          assert.strictEqual(res.code, codes.SERVFAIL);
          assert(res.answer.length === 0);
          assert(!res.ad);
        });
      }
    });
  }
});
