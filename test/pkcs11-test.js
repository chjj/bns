/* eslint-env mocha */
/* eslint prefer-arrow-callback: "off" */

'use strict';

const assert = require('bsert');
const pkcs11js = require('pkcs11js');
const fs = require('fs');
const path = require('path');
const rsa = require('bcrypto/lib/rsa');
const p256 = require('bcrypto/lib/p256');
const pkcs1 = require('bcrypto/lib/encoding/pkcs1');
const constants = require('../lib/constants');
const dnssec = require('../lib/dnssec');
const keys = require('../lib/internal/keys');
const {Record, TXTRecord, types, classes} = require('../lib/wire');
const hsm = require('../lib/hsm');

/*
 * REQUIRES installation of SoftHSMv2:
 * https://github.com/opendnssec/SoftHSMv2
 *
 * Great docs: https://www.cryptsoft.com/pkcs11doc/v230/
 */

const softHSMPath = '/usr/local/lib/softhsm/libsofthsm2.so';

describe('PKCS#11', function() {
  if (!fs.existsSync(softHSMPath)) {
    console.log('SoftHSMv2 library not found.');
    this.skip();
  }

  const label = 'bns-pcks11-test-label';
  const SO_PIN = '5353';
  const USER_PIN = '1234';

  let pkcs11, session, slot;

  const rsaKeyId = Buffer.from('rsakey');
  const ecKeyId = Buffer.from('eckey');
  const foundKeys = [];
  let rsaPublicKey, dnskeyID;

  describe('Connect to HSM and initialize', function() {
    it('should initialize library', () => {
      // Load module
      pkcs11 = new pkcs11js.PKCS11();
      pkcs11.load(softHSMPath);

      // Initialize library
      pkcs11.C_Initialize();
    });

    it('should load module and get info', () => {
      const info = pkcs11.C_GetInfo();
      assert.strictEqual(
        info.manufacturerID,
        'SoftHSM                         '
      );
      assert.strictEqual(
        info.libraryDescription,
        'Implementation of PKCS11        '
      );
    });

    it('should initialize a token in a slot', () => {
      const slots = pkcs11.C_GetSlotList();
      assert(slots.length > 0);
      slot = slots[0];

      const res = pkcs11.C_InitToken(slot, SO_PIN, label);
      assert.strictEqual(res, label);
    });
  });

  describe('Start session and login as security officer', function() {
    it('should open a session', () => {
      session = pkcs11.C_OpenSession(
        slot,
        pkcs11js.CKF_RW_SESSION | pkcs11js.CKF_SERIAL_SESSION
      );
      assert(session);
    });

    it('should login security officer and initialize user PIN', () => {
      pkcs11.C_Login(session, pkcs11js.CKU_SO, SO_PIN);
      pkcs11.C_InitPIN(session, USER_PIN);
      pkcs11.C_Logout(session);
    });
  });

  describe('Login in as user and generate keys', function() {
    it('should log in user', () => {
      pkcs11.C_Login(session, pkcs11js.CKU_USER, USER_PIN);
    });

    it('should not find any objects', () => {
      pkcs11.C_FindObjectsInit(
        session,
        [
          { type: pkcs11js.CKA_LABEL, value: 'bns-pcks11-test-label' }
        ]
      );
      const found = pkcs11.C_FindObjects(session);
      assert.strictEqual(found, null);
      pkcs11.C_FindObjectsFinal(session);
    });

    it('should generate RSA & ECDSA keys', () => {
      // Generate ECDSA key
      // secp256r1 (p256) oid: http://oid-info.com/get/1.2.840.10045.3.1.7
      const oid = '06082A8648CE3D030107';
      const ecKey = pkcs11.C_GenerateKeyPair(
        session,
        { mechanism: pkcs11js.CKM_ECDSA_KEY_PAIR_GEN },
        [
          { type: pkcs11js.CKA_CLASS, value: pkcs11js.CKO_PUBLIC_KEY },
          { type: pkcs11js.CKA_ECDSA_PARAMS, value: Buffer.from(oid, 'hex') },
          { type: pkcs11js.CKA_DERIVE, value: false },
          { type: pkcs11js.CKA_ID, value: ecKeyId},
          { type: pkcs11js.CKA_TOKEN, value: true }
        ], [
          { type: pkcs11js.CKA_CLASS, value: pkcs11js.CKO_PRIVATE_KEY },
          { type: pkcs11js.CKA_DERIVE, value: false },
          { type: pkcs11js.CKA_ID, value: ecKeyId},
          { type: pkcs11js.CKA_TOKEN, value: true }
        ]
      );
      assert(ecKey.publicKey);
      assert(ecKey.privateKey);

      // Generate RSA key
      const rsaKey = pkcs11.C_GenerateKeyPair(
        session,
        { mechanism: pkcs11js.CKM_RSA_PKCS_KEY_PAIR_GEN },
        [
          { type: pkcs11js.CKA_CLASS, value: pkcs11js.CKO_PUBLIC_KEY },
          { type: pkcs11js.CKA_PUBLIC_EXPONENT, value: Buffer.from([1, 0, 1]) },
          { type: pkcs11js.CKA_MODULUS_BITS, value: 2048 },
          { type: pkcs11js.CKA_VERIFY, value: true },
          { type: pkcs11js.CKA_ID, value: rsaKeyId},
          { type: pkcs11js.CKA_TOKEN, value: true }
        ],
        [
          { type: pkcs11js.CKA_CLASS, value: pkcs11js.CKO_PRIVATE_KEY },
          { type: pkcs11js.CKA_SIGN, value: true },
          { type: pkcs11js.CKA_ID, value: rsaKeyId},
          { type: pkcs11js.CKA_TOKEN, value: true }
        ]
      );
      assert(rsaKey.publicKey);
      assert(rsaKey.privateKey);
    });

    it('should find public keys', () => {
      pkcs11.C_FindObjectsInit(
        session,
        [
          { type: pkcs11js.CKA_CLASS, value: pkcs11js.CKO_PUBLIC_KEY }
        ]
      );

      for (;;) {
        const item = pkcs11.C_FindObjects(session);

        if (!item)
          break;

        foundKeys.push(item);
      }

      assert.strictEqual(foundKeys.length, 2);

      pkcs11.C_FindObjectsFinal(session);
    });

    it('should get public key data from found keys', () => {
      for (const key of foundKeys) {
        const attr = pkcs11.C_GetAttributeValue(
          session,
          key,
          [
            { type: pkcs11js.CKA_KEY_TYPE }
          ]
        );
        assert(attr);
        const keyType = attr[0].value;

        // Found an RSA key
        if (keyType.readUInt32LE() === pkcs11js.CKK_RSA) {
          const pubKey = pkcs11.C_GetAttributeValue(
            session,
            key,
            [
              { type: pkcs11js.CKA_MODULUS },
              { type: pkcs11js.CKA_PUBLIC_EXPONENT },
              { type: pkcs11js.CKA_ID }
            ]
          );

          // Test the public key data is valid with bcrypto,
          // and save the key for signature verification.
          rsaPublicKey = rsa.publicKeyImport({
            e: pubKey[1].value,
            n: pubKey[0].value
          });
          assert(rsaPublicKey);

          // Based on the public key, we decide this is the key to sign with
          dnskeyID = pubKey[2].value;
        }

        // Found an ECDSA key
        if (keyType.readUInt32LE() === pkcs11js.CKK_EC ||
            keyType.readUInt32LE() === pkcs11js.CKK_ECDSA
        ) {
          const attr = pkcs11.C_GetAttributeValue(
            session,
            key,
            [
              { type: pkcs11js.CKA_EC_POINT },
              { type: pkcs11js.CKA_ID }
            ]
          );
          assert(attr);
          const pubKey = attr[0].value;

          // The public key (EC point) is DER-encoded.
          // For now, we can assume the first three bytes are:
          // ASN.1 Octet Stream identifier
          assert.strictEqual(pubKey[0], 0x04);
          // Length including compression metadata (65 bytes)
          assert.strictEqual(pubKey[1], 0x41);
          // Point is uncompressed
          assert.strictEqual(pubKey[2], 0x04);

          const x = pubKey.slice(3, 35);
          const y = pubKey.slice(35);

          // Test the public key data is valid with bcrypto
          const ecKey = p256.publicKeyImport({x, y});
          assert(ecKey);
        }
      }
    });

    it('should find and sign with key', () => {
      // First find the privkey that matches the pubkey we selected
      pkcs11.C_FindObjectsInit(
        session,
        [
          { type: pkcs11js.CKA_CLASS, value: pkcs11js.CKO_PRIVATE_KEY },
          { type: pkcs11js.CKA_ID, value: dnskeyID }
        ]
      );
      const priv = pkcs11.C_FindObjects(session);
      assert(priv);

      pkcs11.C_FindObjectsFinal(session);

      pkcs11.C_SignInit(
        session,
        { mechanism: pkcs11js.CKM_RSA_PKCS },
        priv
      );

      const alg = constants.algs['RSASHA256'];
      const hash = dnssec.algToHash[alg];
      const hashID = constants.algHashes[alg];
      const prefix = constants.hashPrefixes[hashID];

      const message = Buffer.from('PKCS#11 is REALLY fun to work with - yay!');
      const hmsg = hash.digest(message);

      // Comment from opendnssec libhsm.c:
      // CKM_RSA_PKCS does the padding, but cannot know the identifier
      // prefix, so we need to add that ourselves.
      // The other algorithms will just get the digest buffer returned.
      const em = Buffer.concat([prefix, hmsg]);

      // C_Sign requires an output buffer as function argument, even though
      // the JavaScript wrapper returns the signature by itself.
      const out = Buffer.alloc(1024);
      const sig = pkcs11.C_Sign(session, em, out);
      assert(sig);

      // Verify signature with bcrypto
      // First parameter is hash function:
      // null   -> signed with CKM_RSA_PKCS (opendnssec does it this way)
      // SHA256 -> signed with CKM_SHA256_RSA_PKCS
      assert(rsa.verify(null, em, sig, rsaPublicKey));
    });
  });

  describe('bns-prove with HSM', function() {
    let dnskeyRSA, dnskeyECDSA;
    let user, slotNumber;

    it('should insert RSA DNSSEC keypair into slot', () => {
      const dnskeyPub = fs.readFileSync(
        path.join(__dirname, 'data/Khns-claim-test-2.xyz.+008+27259.key'),
        'utf8'
      );
      const dnskeyPriv = fs.readFileSync(
        path.join(__dirname, 'data/Khns-claim-test-2.xyz.+008+27259.private'),
        'utf8'
      );

      const dnskey = Record.fromString(dnskeyPub);
      dnskeyRSA = dnskey;
      const pubbuf = dnskey.data.publicKey;
      // https://datatracker.ietf.org/doc/html/rfc2537#section-2
      const pub = {
        elen: pubbuf[0],
        e: pubbuf.slice(1, pubbuf[0] + 1),
        n: pubbuf.slice(pubbuf[0] + 1)
      };

      const [alg, privbuf] = keys.decodePrivate(dnskeyPriv);
      const priv = pkcs1.RSAPrivateKey.decode(privbuf);

      const keyID = Buffer.from(String(dnskey.data.keyTag()));
      const keyType = hsm.algToKeyType[alg];

      const res1 = pkcs11.C_CreateObject(
        session,
        [
          { type: pkcs11js.CKA_CLASS, value: pkcs11js.CKO_PRIVATE_KEY },
          { type: pkcs11js.CKA_KEY_TYPE, value: keyType },
          { type: pkcs11js.CKA_MODULUS, value: priv.n.value },
          { type: pkcs11js.CKA_PUBLIC_EXPONENT, value: priv.e.value },
          { type: pkcs11js.CKA_PRIVATE_EXPONENT, value: priv.d.value },
          { type: pkcs11js.CKA_PRIME_1, value: priv.p.value },
          { type: pkcs11js.CKA_PRIME_2, value: priv.q.value },
          { type: pkcs11js.CKA_EXPONENT_1, value: priv.dp.value },
          { type: pkcs11js.CKA_EXPONENT_2, value: priv.dq.value },
          { type: pkcs11js.CKA_COEFFICIENT, value: priv.qi.value },
          { type: pkcs11js.CKA_SIGN, value: true },
          { type: pkcs11js.CKA_ID, value: keyID },
          { type: pkcs11js.CKA_TOKEN, value: true }
        ]
      );
      assert(res1);

      const res2 = pkcs11.C_CreateObject(
        session,
        [
          { type: pkcs11js.CKA_CLASS, value: pkcs11js.CKO_PUBLIC_KEY },
          { type: pkcs11js.CKA_KEY_TYPE, value: keyType },
          { type: pkcs11js.CKA_PUBLIC_EXPONENT, value: pub.e },
          { type: pkcs11js.CKA_MODULUS, value: pub.n },
          { type: pkcs11js.CKA_VERIFY, value: true },
          { type: pkcs11js.CKA_ID, value: keyID },
          { type: pkcs11js.CKA_TOKEN, value: true }
        ]
      );
      assert(res2);
    });

    it('should insert ECDSA DNSSEC keypair into slot', () => {
      const dnskeyPub = fs.readFileSync(
        path.join(__dirname, 'data/Khns-claim-test-2.xyz.+013+32174.key'),
        'utf8'
      );
      const dnskeyPriv = fs.readFileSync(
        path.join(__dirname, 'data/Khns-claim-test-2.xyz.+013+32174.private'),
        'utf8'
      );

      const dnskey = Record.fromString(dnskeyPub);
      dnskeyECDSA = dnskey;
      const pubbuf = dnskey.data.publicKey;
      const pub = Buffer.alloc(67);
      pub[0] = 0x04;
      pub[1] = 0x41;
      pub[2] = 0x04;
      pubbuf.copy(pub, 3);

      const [alg, priv] = keys.decodePrivate(dnskeyPriv);

      const keyID = Buffer.from(String(dnskey.data.keyTag()));
      const keyType = hsm.algToKeyType[alg];

      const oid = '06082A8648CE3D030107'; // ECDSA P-256
      const res1 = pkcs11.C_CreateObject(
        session,
        [
          { type: pkcs11js.CKA_CLASS, value: pkcs11js.CKO_PRIVATE_KEY },
          { type: pkcs11js.CKA_KEY_TYPE, value: keyType },
          { type: pkcs11js.CKA_EC_PARAMS, value: Buffer.from(oid, 'hex') },
          { type: pkcs11js.CKA_VALUE, value: priv },
          { type: pkcs11js.CKA_SIGN, value: true },
          { type: pkcs11js.CKA_ID, value: keyID },
          { type: pkcs11js.CKA_TOKEN, value: true }
        ]
      );
      assert(res1);

      const res2 = pkcs11.C_CreateObject(
        session,
        [
          { type: pkcs11js.CKA_CLASS, value: pkcs11js.CKO_PUBLIC_KEY },
          { type: pkcs11js.CKA_KEY_TYPE, value: keyType },
          { type: pkcs11js.CKA_EC_PARAMS, value: Buffer.from(oid, 'hex') },
          { type: pkcs11js.CKA_EC_POINT, value: pub },
          { type: pkcs11js.CKA_VERIFY, value: true },
          { type: pkcs11js.CKA_ID, value: keyID },
          { type: pkcs11js.CKA_TOKEN, value: true }
        ]
      );
      assert(res2);
    });

    it('should logout and close current session', () => {
      pkcs11.C_Logout(session);
      pkcs11.C_CloseSession(session);
      pkcs11.C_Finalize();
    });

    it('should get the slot number', () => {
      // SoftHSM does something funny when you create a new slot,
      // the ID remains 0x00 until you completely close
      // the library. When you restart, that slot's real
      // number is available. This simulates the operator
      // getting a list of slots from the HSM, or creating
      // a new slot for us and getting the slot number.
      pkcs11.C_Initialize();
      const slots = pkcs11.C_GetSlotList();
      slotNumber = slots[0].readUInt32LE();
      pkcs11.C_Finalize();
    });

    it('should open HSM session', () => {
      user = new hsm.HSMUser({
        module: softHSMPath,
        slot: slotNumber,
        pin: USER_PIN
      });

      user.open();
    });

    it('should sign a TXT record with corresponding DNSKEYs', () => {
      const txt =
        'hns-regtest:aakkrwicqqs2s5aoxavbcaariycxuze3i5fp2aden2r62z' +
        'x3tjtl3ry56orjwonppjdru3p2uirlbyglvvtcepoqbhdacaaaabdz52s5';
      const rr = new Record();
      const rd = new TXTRecord();
      rr.name = 'hns-claim-test-2.xyz.';
      rr.type = types.TXT;
      rr.class = classes.IN;
      rr.ttl = 3600;
      rr.data = rd;
      rd.txt.push(txt);

      {
        const sig = user.sign(dnskeyRSA, [rr]);
        assert(sig);

        assert(dnssec.verify(sig, dnskeyRSA, [rr]));

        // Sanity check: malleated signature fails
        sig.data.signature[0] = 0;
        assert(!dnssec.verify(sig, dnskeyRSA, [rr]));
      }

      {
        const sig = user.sign(dnskeyECDSA, [rr]);
        assert(sig);

        assert(dnssec.verify(sig, dnskeyECDSA, [rr]));

        // Sanity check: malleated signature fails
        sig.data.signature[0] = 0;
        assert(!dnssec.verify(sig, dnskeyECDSA, [rr]));
      }
    });

    it('should close HSM session', () => {
      user.close();
    });
  });
});
