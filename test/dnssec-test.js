/* eslint-env mocha */
/* eslint prefer-arrow-callback: "off" */

'use strict';

const assert = require('./util/assert');
const Path = require('path');
const fs = require('bfile');
const dnssec = require('../lib/dnssec');
const wire = require('../lib/wire');
const vectors1 = require('./data/dnssec-verify-1.json');
const vectors2 = require('./data/dnssec-verify-2.json');
const vectors3 = require('./data/dnssec-verify-3.json');
const {Record} = wire;

const DSA_TEST = Path.resolve(__dirname, 'data', 'dsa-test.zone');

describe('DNSSEC', function() {
  for (const vectors of [vectors1, vectors2, vectors3]) {
    for (const vector of vectors) {
      const sig = Record.fromHex(vector.sig);
      const key = Record.fromHex(vector.key);
      const rrset = vector.rrset.map(hex => Record.fromHex(hex));
      const result = vector.result;

      it(`should verify signature for: ${sig.name}`, () => {
        assert.strictEqual(dnssec.verify(sig, key, rrset), result);
      });
    }
  }

  {
    const str = fs.readFileSync(DSA_TEST, 'utf8');
    const parts = str.split('\n\n');
    const dsaPriv = parts[1].replace(/^; /gm, '').trim();
    const dsaPub = parts[2].trim();
    const rrset1 = parts[3].trim();
    const rrset2 = parts[4].trim();

    it('should parse private key', () => {
      const [type, priv] = dnssec.decodePrivate(dsaPriv);
      assert(type && priv);
    });

    it('should verify DSA signature (1)', () => {
      const key = Record.fromString(dsaPub);
      const rrset = wire.fromZone(rrset1);
      const sig = rrset.pop();

      assert.strictEqual(dnssec.verify(sig, key, rrset), true);
    });

    it('should verify DSA signature (2)', () => {
      const key = Record.fromString(dsaPub);
      const rrset = wire.fromZone(rrset2);
      const sig = rrset.pop();

      assert.strictEqual(dnssec.verify(sig, key, rrset), true);
    });
  }
});
