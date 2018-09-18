/* eslint-env mocha */
/* eslint prefer-arrow-callback: "off" */

'use strict';

const assert = require('./util/assert');
const nsec3 = require('../lib/nsec3');
const wire = require('../lib/wire');
const vectors = require('./data/nsec3-vectors.json');
const {Question, Record} = wire;

describe('NSEC3', function() {
  for (const vector of vectors.hash_name) {
    const name = vector.name;
    const ha = vector.ha;
    const iter = vector.iter;
    const salt = Buffer.from(vector.salt, 'hex');
    const result = vector.result != null
      ? Buffer.from(vector.result, 'hex')
      : null;

    it(`should hash name: ${name}`, () => {
      const res = nsec3.hashName(name, ha, iter, salt);

      if (!result)
        assert.strictEqual(res, result);
      else
        assert.bufferEqual(res, result);
    });
  }

  for (const vector of vectors.cover) {
    const rr = Record.fromHex(vector.rr);
    const name = vector.name;
    const result = vector.result;

    it(`should cover ${name}`, () => {
      assert.strictEqual(nsec3.cover(rr, name), result);
    });
  }

  for (const vector of vectors.match) {
    const rr = Record.fromHex(vector.rr);
    const name = vector.name;
    const result = vector.result;

    it(`should match ${name}`, () => {
      assert.strictEqual(nsec3.match(rr, name), result);
    });
  }

  for (const vector of vectors.find_closest_encloser) {
    const name = vector.name;
    const nsec = vector.nsec.map(hex => Record.fromHex(hex));
    const result = vector.result;

    it(`should find closest encloser for ${name}`, () => {
      assert.deepStrictEqual(nsec3.findClosestEncloser(name, nsec), result);
    });
  }

  for (const vector of vectors.find_coverer) {
    const name = vector.name;
    const nsec = vector.nsec.map(hex => Record.fromHex(hex));
    const result = vector.result[0] != null
      ? [Buffer.from(vector.result[0], 'hex'), vector.result[1]]
      : vector.result;

    it(`should find coverer for ${name}`, () => {
      assert.deepStrictEqual(nsec3.findCoverer(name, nsec), result);
    });
  }

  for (const vector of vectors.verify_name_error) {
    const qs = Question.fromHex(vector.qs);
    const nsec = vector.nsec.map(hex => Record.fromHex(hex));
    const result = vector.result;

    it(`should verify NXDOMAIN for ${qs.name}`, () => {
      assert.strictEqual(nsec3.verifyNameError(qs, nsec), result);
    });
  }

  for (const vector of vectors.verify_no_data) {
    const qs = Question.fromHex(vector.qs);
    const nsec = vector.nsec.map(hex => Record.fromHex(hex));
    const result = vector.result;

    it(`should verify NODATA for ${qs.name}`, () => {
      assert.strictEqual(nsec3.verifyNoData(qs, nsec), result);
    });
  }

  for (const vector of vectors.verify_delegation) {
    const delegation = vector.delegation;
    const nsec = vector.nsec.map(hex => Record.fromHex(hex));
    const result = vector.result;

    it(`should verify delegation for ${delegation}`, () => {
      assert.strictEqual(nsec3.verifyDelegation(delegation, nsec), result);
    });
  }
});
