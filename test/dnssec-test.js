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
const vectors4 = require('./data/dnssec-verify-4.json');
const vectors5 = require('./data/dnssec-verify-5.json');
const {algs, keyFlags} = dnssec;
const {Record} = wire;

const DSA_TEST = Path.resolve(__dirname, 'data', 'dsa-test.zone');
const ED25519_TEST = Path.resolve(__dirname, 'data', 'ed25519-test.zone');
const KEY_DIR = Path.resolve(__dirname, 'data');

describe('DNSSEC', function() {
  for (const vectors of [vectors1, vectors2, vectors3, vectors4, vectors5]) {
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
    const str = fs.readFileSync(ED25519_TEST, 'utf8');
    const parts = str.split('\n\n');
    const keyText = parts[1].trim();
    const rrText = parts[2].trim();
    const sigText = parts[3].trim();
    const key = Record.fromString(keyText);
    const rr = Record.fromString(rrText);
    const sig = Record.fromString(sigText);

    it(`should verify signature for: ${sig.name}`, () => {
      assert.strictEqual(dnssec.verify(sig, key, [rr]), true);
    });
  }

  {
    const str = fs.readFileSync(DSA_TEST, 'utf8');
    const parts = str.split('\n\n');
    const dsaPriv = parts[1].replace(/^; /gm, '').trim();
    const dsaPub = parts[2].trim();
    const rrset1 = parts[3].trim();
    const rrset2 = parts[4].trim();

    it('should parse DSA private key', async () => {
      const [alg, priv] = dnssec.decodePrivate(dsaPriv);

      assert.strictEqual(alg, algs.DSA);
      assert(Buffer.isBuffer(priv));

      const key = Record.fromString(dsaPub);
      const ds = dnssec.createDS(key);

      dnssec.writeKeys(KEY_DIR, key, priv, 1537312145);

      const key2 = dnssec.readPublic(KEY_DIR, ds);

      assert.bufferEqual(key.encode(), key2.encode());

      await dnssec.writeKeysAsync(KEY_DIR, key, priv, 1537312145);

      const key3 = await dnssec.readPublicAsync(KEY_DIR, ds);

      assert.bufferEqual(key.encode(), key3.encode());
    });

    it('should create DSA private key and read public key', async () => {
      const [alg, priv] = dnssec.decodePrivate(dsaPriv);

      assert.strictEqual(alg, algs.DSA);
      assert(Buffer.isBuffer(priv));

      const key = dnssec.makeKey('nlnetlabs.nl.', alg, priv, keyFlags.ZSK);
      key.ttl = 3600;

      const ds = dnssec.createDS(key);
      const key2 = dnssec.readPublic(KEY_DIR, ds);

      assert.bufferEqual(key.encode(), key2.encode());
      assert.bufferEqual(key.encode(), Record.fromString(dsaPub).encode());

      const key3 = await dnssec.readPublicAsync(KEY_DIR, ds);
      assert.bufferEqual(key.encode(), key3.encode());
    });

    it('should read DSA private key', async () => {
      const [alg, priv] = dnssec.decodePrivate(dsaPriv);

      assert.strictEqual(alg, algs.DSA);
      assert(Buffer.isBuffer(priv));

      const key = Record.fromString(dsaPub);
      const priv2 = dnssec.readPrivate(KEY_DIR, key);

      assert.bufferEqual(priv, priv2);

      const priv3 = await dnssec.readPrivateAsync(KEY_DIR, key);

      assert.bufferEqual(priv, priv3);
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

  for (const alg of [
    algs.RSAMD5,
    algs.DSA,
    algs.RSASHA1,
    algs.DSANSEC3SHA1,
    algs.RSASHA1NSEC3SHA1,
    algs.RSASHA256,
    algs.RSASHA512,
    algs.ECDSAP256SHA256,
    algs.ECDSAP384SHA384,
    algs.ED25519
  ]) {
    let bits = 2048;

    if (alg === algs.DSA || alg === algs.DSANSEC3SHA1)
      bits = 1024;

    it(`should generate key and sign (${wire.algToString(alg)})`, async () => {
      const priv = await dnssec.createPrivateAsync(alg, bits);
      const key = dnssec.makeKey('example.com.', alg, priv, keyFlags.ZSK);

      assert.bufferEqual(
        dnssec.decodePrivate(dnssec.encodePrivate(alg, priv))[1],
        priv);

      const rr = new wire.Record();
      const rd = new wire.TXTRecord();

      rr.name = 'example.com.';
      rr.type = wire.types.TXT;
      rr.ttl = 3600;
      rr.data = rd;
      rd.txt.push('Hello world');

      const sig = dnssec.sign(key, priv, [rr]);

      assert(dnssec.verify(sig, key, [rr]));
    });
  }
});
