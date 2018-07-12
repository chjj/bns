/*!
 * root.js - root dns resolver for bns
 * Copyright (c) 2018, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bns
 */

'use strict';

const assert = require('assert');
const DNSResolver = require('./dns');
const dnssec = require('../dnssec');
const Hints = require('../hints');
const util = require('../util');
const wire = require('../wire');

const {
  Question,
  Message,
  types,
  codes
} = wire;

/**
 * RootResolver
 * @extends DNSResolver
 */

class RootResolver extends DNSResolver {
  constructor(options) {
    super(options);

    this.rd = false;
    this.edns = true;
    this.dnssec = true;
    this.hints = new Hints();
    this.hints.setRoot();
    this.zskMap = null;
    this.revSet = null;
    this.lastKey = 0;

    this.initOptions(options);
  }

  initOptions(options) {
    if (options == null)
      return this;

    this.parseOptions(options);

    if (options.hints != null) {
      assert(options.hints instanceof Hints);
      this.hints = options.hints;
    }

    return this;
  }

  getAuthority() {
    return this.hints.getAuthority(this.inet6);
  }

  async lookupDNSKEY(qs, auth) {
    const ds = this.hints.anchors;
    const res = await this.query(qs, auth.servers);

    if (res.answer.length === 0
        || res.code !== codes.NOERROR) {
      return [null, null];
    }

    // Pick out the valid KSK's.
    const kskMap = dnssec.verifyDS(res, ds, qs.name);

    if (!kskMap)
      return [null, null];

    // Verify all ZSK's with KSK's.
    if (!dnssec.verifyZSK(res, kskMap, qs.name))
      return [null, null];

    const zskMap = new Map();
    const revSet = new Set();

    // Grab all ZSK's from the answer.
    for (const rr of res.answer) {
      if (rr.type !== types.DNSKEY)
        continue;

      const rd = rr.data;

      if (!util.equal(rr.name, qs.name))
        continue;

      if (!(rd.flags & dnssec.keyFlags.ZONE))
        continue;

      if (rd.flags & dnssec.keyFlags.REVOKE) {
        revSet.add(rd.revTag());
        continue;
      }

      zskMap.set(rd.keyTag(), rr);
    }

    return [zskMap, revSet];
  }

  async checkSignatures(msg, auth) {
    if (!this.dnssec)
      return true;

    const now = util.now();

    if (!this.zskMap || now > this.lastKey + 6 * 60 * 60) {
      const qs = new Question(auth.zone, types.DNSKEY);
      const [zskMap, revSet] = await this.lookupDNSKEY(qs, auth);

      if (!zskMap)
        return false;

      this.zskMap = zskMap;
      this.revSet = revSet;
      this.lastKey = now;
    }

    if (!dnssec.verifyMessage(msg, this.zskMap, this.revSet))
      return false;

    return true;
  }

  async resolve(qs) {
    assert(qs instanceof Question);

    if (!util.isName(qs.name))
      throw new Error('Invalid qname.');

    const auth = this.getAuthority();
    const res = await this.query(qs, auth.servers);
    const ad = await this.checkSignatures(res, auth);

    const msg = new Message();
    msg.code = res.code;
    msg.question = [qs.clone()];
    msg.answer = res.answer;
    msg.authority = res.authority;
    msg.additional = res.additional;
    msg.qr = true;
    msg.ad = ad;

    dnssec.stripSignatures(msg);

    return msg;
  }

  async lookup(name) {
    const qs = new Question(name, types.NS);
    return this.resolve(qs);
  }
}

/*
 * Expose
 */

module.exports = RootResolver;
