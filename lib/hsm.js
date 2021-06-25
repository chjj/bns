/* eslint no-case-declarations: "off" */

/*!
 * hsm.js - HSM PKCS#11 interface for bns
 * Copyright (c) 2021, Matthew Zipkin (MIT License).
 * https://github.com/chjj/bns
 */

'use strict';

const assert = require('bsert');
const pkcs11js = require('pkcs11js');
const constants = require('./constants');
const dnssec = require('./dnssec');
const util = require('./util');
const {Record, DNSKEYRecord, RRSIGRecord, types} = require('./wire');

const {algs} = constants;

// Comment from pkcs11js pkcs11t.h:
// CKK_ECDSA is deprecated in v2.11, CKK_EC is preferred.
const algToKeyType = {
  [algs.RSASHA1]: pkcs11js.CKK_RSA,
  [algs.RSASHA256]: pkcs11js.CKK_RSA,
  [algs.ECDSAP256SHA256]: pkcs11js.CKK_EC,
  [algs.RSASHA512]: pkcs11js.CKK_RSA
};

const algToMechanism = {
  [algs.RSASHA1]: pkcs11js.CKM_RSA_PKCS,
  [algs.RSASHA256]: pkcs11js.CKM_RSA_PKCS,
  [algs.ECDSAP256SHA256]: pkcs11js.CKM_ECDSA,
  [algs.RSASHA512]: pkcs11js.CKM_RSA_PKCS
};

class HSMUser {
  constructor(options) {
    this.module = null;
    this.pkcs11 = null;
    this.session = null;
    this.slot = Buffer.alloc(8);
    this.pin = null;

    if (options)
      this.fromOptions(options);
  }

  fromOptions(options) {
    if (options.module != null) {
      assert(typeof options.module === 'string');
      this.module = options.module;
    }

    if (options.slot != null) {
      assert(Number.isSafeInteger(options.slot));
      assert(options.slot >= 0);
      assert(options.slot <= 0xffffffff);
      this.slot.writeUInt32LE(options.slot);
    }

    if (options.pin != null) {
      assert(typeof options.pin === 'string');
      this.pin = options.pin;
    }
  }

  open() {
    // Load module
    this.pkcs11 = new pkcs11js.PKCS11();
    this.pkcs11.load(this.module);

    // Initialize library
    this.pkcs11.C_Initialize();

    // Create read-only session
    // by not setting pkcs11js.CKF_RW_SESSION flag
    this.session = this.pkcs11.C_OpenSession(
      this.slot,
      pkcs11js.CKF_SERIAL_SESSION
    );

    // Login in user
    this.pkcs11.C_Login(this.session, pkcs11js.CKU_USER, this.pin);
  }

  sign(dnskey, rrset) {
    assert(dnskey instanceof Record);
    assert(dnskey.data instanceof DNSKEYRecord);
    assert(util.isRRSet(rrset));

    // Use DNSKEY record to find the private key we need to sign with
    const [alg, pub] = this.extractPublicKey(dnskey);
    const priv = this.getPrivForPub(alg, pub);

    // Prepare data for signing
    const sig = new Record();
    const rd = new RRSIGRecord();
    sig.name = dnskey.name;
    sig.ttl = dnskey.ttl;
    sig.class = dnskey.class;
    sig.type = types.RRSIG;
    sig.data = rd;
    rd.keyTag = dnskey.data.keyTag();
    rd.signerName = dnskey.name;
    rd.algorithm = alg;
    rd.inception = util.now() - (24 * 60 * 60);
    rd.expiration = util.now() + (365 * 24 * 60 * 60);
    rd.origTTL = rrset[0].ttl;
    rd.typeCovered = rrset[0].type;
    rd.labels = util.countLabels(rrset[0].name);

    if (rrset[0].name[0] === '*')
      rd.labels -= 1;

    const data = dnssec.signatureHash(sig, rrset);
    const hash = dnssec.algToHash[alg];
    const hmsg = hash.digest(data);
    // Comment from opendnssec libhsm.c:
    // CKM_RSA_PKCS does the padding, but cannot know the identifier
    // prefix, so we need to add that ourselves.
    // The other algorithms will just get the digest buffer returned.
    const hashID = constants.algHashes[alg];
    const prefix = constants.hashPrefixes[hashID];
    const em = Buffer.concat([prefix, hmsg]);

    // Sign with HSM!
    this.pkcs11.C_SignInit(
      this.session,
      { mechanism: algToMechanism[alg] },
      priv
    );

    // C_Sign requires an output buffer as function argument, even though
    // the JavaScript wrapper returns the signature by itself.
    const out = Buffer.alloc(1024);
    rd.signature = this.pkcs11.C_Sign(this.session, em, out);

    return sig;
  }

  extractPublicKey(dnskey) {
    const alg = dnskey.data.algorithm;
    const pubbuf = dnskey.data.publicKey;

    let pub;
    switch (alg) {
      case algs.RSASHA1:
      case algs.RSASHA256:
      case algs.RSASHA512:
        // https://datatracker.ietf.org/doc/html/rfc2537#section-2
        pub = {
          elen: pubbuf[0],
          e: pubbuf.slice(1, pubbuf[0] + 1),
          n: pubbuf.slice(pubbuf[0] + 1)
        };
        break;
      case algs.ECDSAP256SHA256:
      case algs.ECDSAP384SHA384:
        // https://datatracker.ietf.org/doc/html/rfc6605#section-4
        pub = pubbuf;
        break;
      default:
        throw new Error('Algorithm not implemented.');
    }

    return [alg, pub];
  }

  getPrivForPub(alg, pub) {
    const template = [
      { type: pkcs11js.CKA_CLASS, value: pkcs11js.CKO_PUBLIC_KEY },
      { type: pkcs11js.CKA_KEY_TYPE, value: algToKeyType[alg] }
    ];

    switch (alg) {
      case algs.RSASHA1:
      case algs.RSASHA256:
      case algs.RSASHA512:
        template.push({ type: pkcs11js.CKA_MODULUS, value: pub.n });
        template.push({ type: pkcs11js.CKA_PUBLIC_EXPONENT, value: pub.e });
        break;
      case algs.ECDSAP256SHA256:
      case algs.ECDSAP384SHA384:
        // The public key (EC point) is DER-encoded.
        // For now, we can assume the first three bytes are:
        // - ASN.1 Octet Stream identifier
        // - Length including compression flag (65 bytes)
        // - Uncompressed point flag
        const meta = Buffer.from([0x04, 0x41, 0x04]);
        const enc = Buffer.concat(meta, pub);
        template.push({ type: pkcs11js.CKA_EC_POINT, value: enc });
        break;
      default:
        throw new Error('Algorithm not implemented.');
    }

    this.pkcs11.C_FindObjectsInit(this.session, template);
    const foundPub = this.pkcs11.C_FindObjects(this.session);
    this.pkcs11.C_FindObjectsFinal(this.session);

    if (!foundPub)
      throw new Error('Could not find public key.');

    // Get the key ID of the matching public key.
    // It's not a strict protocol rule, but public/private key pairs
    // should always have matching Key IDs:
    // https://www.cryptsoft.com/pkcs11doc/v230/group__SEC__9__7__KEY__OBJECTS.html
    const attr = this.pkcs11.C_GetAttributeValue(
      this.session,
      foundPub,
      [
        { type: pkcs11js.CKA_ID }
      ]
    );
    const keyID = attr[0].value;

    // Now we go find the private key with that key ID...
    this.pkcs11.C_FindObjectsInit(
      this.session,
      [
        { type: pkcs11js.CKA_CLASS, value: pkcs11js.CKO_PRIVATE_KEY },
        { type: pkcs11js.CKA_ID, value: keyID }
      ]
    );
    const foundPriv = this.pkcs11.C_FindObjects(this.session);
    this.pkcs11.C_FindObjectsFinal(this.session);

    if (!foundPriv)
      throw new Error('Could not find private key.');

    return foundPriv;
  }
}

exports.HSMUser = HSMUser;
exports.algToKeyType = algToKeyType;
