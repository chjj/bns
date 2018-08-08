/*!
 * root.js - root dns resolver for bns
 * Copyright (c) 2018, Christopher Jeffrey (MIT License).
 * https://github.com/chjj/bns
 */

'use strict';

const assert = require('bsert');
const constants = require('../constants');
const DNSResolver = require('./dns');
const dnssec = require('../dnssec');
const Hints = require('../hints');
const ROOT_HINTS = require('../roothints');
const util = require('../util');
const wire = require('../wire');

const {
  types,
  codes,
  KSK_ARPA
} = constants;

const {
  hasType,
  extractSet
} = util;

const {
  Question,
  Message,
  Record
} = wire;

/*
 * Constants
 */

const CACHE_TIME = 6 * 60 * 60;

/**
 * RootResolver
 * @extends DNSResolver
 */

class RootResolver extends DNSResolver {
  constructor(options) {
    super(options);

    const hints = getHints(this.inet6);

    this.rd = false;
    this.edns = true;
    this.dnssec = true;
    this.anchors = hints.anchors;
    this.servers = hints.servers;
    this.keyMap = new Map();
    this.lastUpdate = 0;
    this.arpa = null;

    if (options)
      this.initOptions(options);
  }

  initOptions(options) {
    this.parseOptions(options);
    return this;
  }

  referArpa(qs) {
    assert(qs instanceof Question);

    if (!this.arpa)
      this.arpa = buildArpa();

    const msg = Message.decode(this.arpa);
    msg.question.push(qs.clone());
    return msg;
  }

  async lookupKeys(zone, ds) {
    const qs = new Question(zone, types.DNSKEY);
    const res = await this.query(qs, this.servers);

    const keyMap = new Map();

    if (res.answer.length === 0
        || res.code !== codes.NOERROR) {
      return null;
    }

    // Pick out the valid KSK's.
    const kskMap = dnssec.verifyDS(res, ds, qs.name);

    if (!kskMap)
      return null;

    // Verify all ZSK's with KSK's.
    if (!dnssec.verifyZSK(res, kskMap, qs.name))
      return null;

    const revoked = new Set();

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
        revoked.add(rd.revTag());
        continue;
      }

      keyMap.set(rd.keyTag(), rr);
    }

    for (const tag of revoked)
      keyMap.delete(tag);

    return keyMap;
  }

  isStale() {
    return util.now() > this.lastUpdate + CACHE_TIME;
  }

  async refreshKeys() {
    const keyMap = await this.lookupKeys('.', this.anchors);

    if (keyMap) {
      this.keyMap = keyMap;
      this.lastUpdate = util.now();
    }
  }

  async checkSignatures(msg) {
    if (!this.dnssec)
      return true;

    if (msg.code !== codes.NOERROR
        && msg.code !== codes.NXDOMAIN) {
      return false;
    }

    if (this.isStale())
      await this.refreshKeys();

    if (!dnssec.verifyMessage(msg, this.keyMap))
      return false;

    if (msg.code === codes.NXDOMAIN)
      return true;

    if (!hasType(msg.authority, types.NS))
      return false;

    if (hasType(msg.authority, types.DS))
      return true;

    const set = extractSet(msg.authority, '', types.NSEC);

    if (set.length !== 1)
      return false;

    const nsec = set[0].data;

    if (!nsec.hasType(types.NS))
      return false;

    if (nsec.hasType(types.DS))
      return false;

    if (nsec.hasType(types.SOA))
      return false;

    return true;
  }

  async resolve(qs) {
    assert(qs instanceof Question);

    if (!util.isName(qs.name))
      throw new Error('Invalid qname.');

    if (util.countLabels(qs.name) !== 1)
      throw new Error('Invalid qname.');

    // Special case for arpa.
    if (util.equal(qs.name, 'arpa.'))
      return this.referArpa(qs);

    const res = await this.query(qs, this.servers);
    const ad = await this.checkSignatures(res);

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
 * Helpers
 */

function getHints(inet6) {
  const hints = new Hints();

  hints.setRoot();

  const auth = hints.getAuthority(inet6);

  return {
    anchors: hints.anchors,
    servers: auth.servers
  };
}

function buildArpa() {
  const rrs = wire.fromZone(ROOT_HINTS);
  const msg = new Message();

  msg.qr = true;
  msg.ad = true;

  for (const rr of rrs) {
    switch (rr.type) {
      case types.NS:
        rr.name = 'arpa.';
        rr.canonical();
        msg.authority.push(rr);
        break;
      case types.A:
      case types.AAAA:
        rr.canonical();
        msg.additional.push(rr);
        break;
    }
  }

  const ds = Record.fromString(KSK_ARPA);

  msg.authority.push(ds);

  return msg.compress();
}

/*
 * Expose
 */

module.exports = RootResolver;
