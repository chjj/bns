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
const ED448_TEST = Path.resolve(__dirname, 'data', 'ed448-test.zone');
const KEY_DIR = Path.resolve(__dirname, 'data');

describe('DNSSEC', function() {
  this.timeout(40000);

  for (const vectors of [vectors1, vectors2, vectors3, vectors4, vectors5]) {
    it(`should parse and verify ${vectors.length} signatures`, () => {
      for (const vector of vectors) {
        const sig = Record.fromHex(vector.sig);
        const key = Record.fromHex(vector.key);
        const rrset = vector.rrset.map(hex => Record.fromHex(hex));
        const result = vector.result;

        assert.strictEqual(dnssec.verify(sig, key, rrset), result);
      }
    });
  }

  {
    const str = fs.readFileSync(ED25519_TEST, 'utf8');
    const parts = str.split('\n\n');
    const keyText = parts[1].trim();
    const rrText = parts[2].trim();
    const sigText = parts[3].trim();

    it('should parse and verify ED25519 signature', () => {
      const key = Record.fromString(keyText);
      const rr = Record.fromString(rrText);
      const sig = Record.fromString(sigText);

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

  it('should create GOST94 DS record', () => {
    // https://tools.ietf.org/html/rfc5933#section-4.1
    const rrText = `
      example.net. 86400 DNSKEY  257 3 12 (
        LMgXRHzSbIJGn6i16K+sDjaDf/k1o9DbxScO
        gEYqYS/rlh2Mf+BRAY3QHPbwoPh2fkDKBroF
        SRGR7ZYcx+YIQw==
      ) ; key id = 40692
    `.replace(/^ +/gm, '');

    const dsText = `
      example.net. 3600 IN DS 40692 12 3 (
        22261A8B0E0D799183E35E24E2AD6BB58533CBA7E3B14D659E9CA09B
        2071398F
      )
    `.replace(/^ +/gm, '');

    const rr = Record.fromString(rrText);
    const ds = dnssec.createDS(rr, dnssec.hashes.GOST94);
    const expect = Record.fromString(dsText);

    assert.bufferEqual(ds.data.digest, expect.data.digest);
  });

  {
    const str = fs.readFileSync(ED448_TEST, 'utf8');
    const parts = str.split(/\n+/);
    const keyText = parts[0].trim();
    const rrText = parts[1].trim();
    const sigText = parts[2].trim();

    it('should verify ed448 signature', () => {
      const key = Record.fromString(keyText);
      const rr = Record.fromString(rrText);
      const sig = Record.fromString(sigText);

      assert.strictEqual(dnssec.verify(sig, key, [rr]), true);
      sig.data.signature[sig.data.signature.length * Math.random() | 0] ^= 1;
      assert.strictEqual(!dnssec.verify(sig, key, [rr]), true);
    });
  }
});
