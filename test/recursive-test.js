/* eslint-env mocha */
/* eslint prefer-arrow-callback: "off" */

'use strict';

const assert = require('./util/assert');
const rdns = require('../lib/rdns');
const {types, codes} = require('../lib/wire');

const dnssecNames = [
  'dnssec-name-and-shame.com',
  'getdnsapi.net',
  'nlnetlabs.nl',
  'nlnet.nl',
  'labs.verisigninc.com',
  'iis.se',
  'www.kirei.se',
  'www.opendnssec.org',
  'www.ietf.org',
  'www.iana.org',
  'internetsociety.org'
];

const nxNames = [
  'ww.dnssec-name-and-shame.com',
  'ww.getdnsapi.net',
  'ww.nlnet.nl',
  'ww.opendnssec.org',
  'nxdomain1234567890.be',
  'nx.nxdomain1234567890.be'
];

const nodataNames = [
  'dnssec-name-and-shame.com',
  'getdnsapi.net',
  'nlnet.nl',
  'www.opendnssec.org'
];

const noDnssecNames = [
  'google.com'
];

const noNxNames = [
  'nxdomain.google.com'
];

const noNodataNames = [
  'google.com'
];

describe('Recursive', function() {
  this.timeout(10000);

  for (const name of dnssecNames) {
    it(`should validate trust chain for ${name}`, async () => {
      const res = await rdns.resolveRaw(name, types.A);
      assert.strictEqual(res.code, codes.NOERROR);
      assert(res.answer.length > 0);
      assert(res.ad);
    });
  }

  for (const name of nxNames) {
    it(`should validate NX proof for ${name}`, async () => {
      const res = await rdns.resolveRaw(name, types.A);
      assert.strictEqual(res.code, codes.NXDOMAIN);
      assert(res.answer.length === 0);
      assert(res.ad);
    });
  }

  for (const name of nodataNames) {
    it(`should validate NODATA proof for ${name}`, async () => {
      const res = await rdns.resolveRaw(name, types.WKS);
      assert.strictEqual(res.code, codes.NOERROR);
      assert(res.answer.length === 0);
      assert(res.ad);
    });
  }

  for (const name of noDnssecNames) {
    it(`should fail to validate trust chain for ${name}`, async () => {
      const res = await rdns.resolveRaw(name, types.A);
      assert.strictEqual(res.code, codes.NOERROR);
      assert(res.answer.length > 0);
      assert(!res.ad);
    });
  }

  for (const name of noNxNames) {
    it(`should fail to validate NX proof for ${name}`, async () => {
      const res = await rdns.resolveRaw(name, types.A);
      assert.strictEqual(res.code, codes.NXDOMAIN);
      assert(res.answer.length === 0);
      assert(!res.ad);
    });
  }

  for (const name of noNodataNames) {
    it(`should fail to validate NODATA proof for ${name}`, async () => {
      const res = await rdns.resolveRaw(name, types.WKS);
      assert.strictEqual(res.code, codes.NOERROR);
      assert(res.answer.length === 0);
      assert(!res.ad);
    });
  }
});
