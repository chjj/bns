/*!
 * recursive.js - recursive dns resolver for bns
 * Copyright (c) 2018, Christopher Jeffrey (MIT License).
 * https://github.com/chjj/bns
 *
 * Parts of this software are based on solvere:
 *   https://github.com/rolandshoemaker/solvere
 */

'use strict';

const assert = require('bsert');
const IP = require('binet');
const Authority = require('../authority');
const Cache = require('../cache');
const constants = require('../constants');
const DNSResolver = require('./dns');
const dnssec = require('../dnssec');
const encoding = require('../encoding');
const Hints = require('../hints');
const nsec3 = require('../nsec3');
const util = require('../util');
const wire = require('../wire');
const {DNS_PORT} = constants;

const {
  Message,
  Question,
  Record,
  types,
  typeToString,
  codes
} = wire;

const {
  extractSet,
  filterSet,
  hasAll,
  hasType,
  random,
  randomItem,
  equal,
  isSubdomain
} = util;

/**
 * RecursiveResolver
 * @extends DNSResolver
 */

class RecursiveResolver extends DNSResolver {
  constructor(options) {
    super(options);

    this.rd = false;
    this.cache = new Cache();
    this.hints = new Hints();
    this.maxReferrals = 30;
    this.minimize = false;
    this.ub = null;

    this.initOptions(options);
  }

  initOptions(options) {
    if (options == null)
      return this;

    this.parseOptions(options);

    if (options.cache != null) {
      assert(options.cache instanceof Cache);
      this.cache = options.cache;
    }

    if (options.hints != null) {
      assert(options.hints instanceof Hints);
      this.hints = options.hints;
    }

    if (options.maxReferrals != null) {
      assert((options.maxReferrals >>> 0) === options.maxReferrals);
      this.maxReferrals = options.maxReferrals;
    }

    if (options.cacheSize != null) {
      assert((options.cacheSize >>> 0) === options.cacheSize);
      this.cache.maxSize = options.cacheSize;
    }

    if (options.minimize != null) {
      assert(typeof options.minimize === 'boolean');
      this.minimize = options.minimize;
    }

    return this;
  }

  setStub(host, port, ds) {
    assert(typeof host === 'string');
    assert((port & 0xffff) === port);
    assert(port !== 0);
    assert(ds instanceof Record);
    assert(ds.type === types.DS);

    const ip = IP.normalize(host);

    this.hints.clear();
    this.hints.ns.push('hints.local.');

    if (IP.isIPv4String(ip))
      this.hints.inet4.set('hints.local.', ip);
    else
      this.hints.inet6.set('hints.local.', ip);

    this.hints.anchors.push(ds.clone());
    this.hints.port = port;

    return this;
  }

  getAuthority() {
    return this.hints.getAuthority(this.inet6);
  }

  async ask(qs, auth) {
    const cache = this.cache.hit(qs, auth.zone);

    if (cache) {
      this.log('Cache hit for %s (%s).', qs.name, typeToString(qs.type));
      return [cache, true];
    }

    const res = await this.query(qs, auth.servers);

    return [res, false];
  }

  async findNS(rc, name, type, zone) {
    const qs = new Question(name, type);
    const child = await this.follow(qs, rc.hops);
    const res = child.toAnswer();

    rc.hops = child.hops;

    if (res.code !== codes.NOERROR)
      throw new Error('Authority lookup failed.');

    const addrs = extractSet(res.answer, name, type);

    if (addrs.length === 0)
      throw new Error('No authority address.');

    const auth = new Authority(zone, name);

    for (const addr of addrs)
      auth.add(addr.data.address, DNS_PORT);

    this.log('Picked nameserver for: %s', name);

    return auth;
  }

  async lookupNS(rc, name, zone) {
    rc.hop();

    if (this.inet6) {
      this.log('Looking up IPv6 nameserver for %s...', name);
      try {
        return await this.findNS(rc, name, types.AAAA, zone);
      } catch (e) {
        this.log('IPv6 nameserver lookup failed: %s', e.message);
      }
    }

    this.log('Looking up IPv4 nameserver for %s...', name);

    return this.findNS(rc, name, types.A, zone);
  }

  async lookupDNSKEY(qs, auth, ds) {
    const [res, hit] = await this.ask(qs, auth);

    if (res.answer.length === 0
        || res.code !== codes.NOERROR) {
      return [new Map(), new Set()];
    }

    if (auth.zone === '.') {
      assert(ds.length === 0);
      ds = this.hints.anchors;
    }

    if (ds.length === 0) {
      this.log('Invalid DNSKEY (DS absent).');
      return [null, null];
    }

    // Pick out the valid KSK's.
    const kskMap = dnssec.verifyDS(res, ds, qs.name);

    if (!kskMap) {
      this.log('Invalid KSKs (DS mismatch).');
      return [null, null];
    }

    if (!hit) {
      // Verify all ZSK's with KSK's if we're not cached.
      if (!dnssec.verifyZSK(res, kskMap, qs.name)) {
        this.log('Invalid KSKs (verification failure).');
        return [null, null];
      }

      const eternal = auth.zone === '.';
      this.cache.insert(qs, auth.zone, res, true, eternal);
    }

    const zskMap = new Map();
    const revSet = new Set();

    // Grab all ZSK's from the answer.
    for (const rr of res.answer) {
      if (rr.type !== types.DNSKEY)
        continue;

      const rd = rr.data;

      if (!equal(rr.name, qs.name))
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

  async checkSignatures(msg, auth, ds) {
    if (!this.dnssec)
      return true;

    const qs = new Question(auth.zone, types.DNSKEY);
    const [zskMap, revSet] = await this.lookupDNSKEY(qs, auth, ds);

    if (!zskMap)
      return false;

    if (zskMap.size === 0) {
      this.log('No ZSKs found.');
      return false;
    }

    if (!dnssec.verifyMessage(msg, zskMap, revSet)) {
      this.log('Invalid RRSIGs.');
      return false;
    }

    this.log('Validated DNSSEC signatures.');

    return true;
  }

  splitAuths(authority, additional) {
    const zones = new Map();
    const nsmap = new Map();

    for (const rr of authority) {
      if (rr.type === types.NS)
        nsmap.set(rr.data.ns.toLowerCase(), rr.name.toLowerCase());
    }

    for (const rr of additional) {
      const zone = nsmap.get(rr.name.toLowerCase());

      if (!zone)
        continue;

      if (this.inet6) {
        if (rr.type !== types.A && rr.type !== types.AAAA)
          continue;
      } else {
        if (rr.type !== types.A)
          continue;
      }

      let items = zones.get(zone);

      if (!items) {
        items = [];
        zones.set(zone, items);
      }

      items.push(rr.data.address);
    }

    return [zones, nsmap];
  }

  async pickAuthority(rc, authority, additional) {
    const [zones, nsmap] = this.splitAuths(authority, additional);

    if (zones.size === 0) {
      if (nsmap.size === 0)
        return null;

      let i = random(nsmap.size);
      let ns, zone;

      for ([ns, zone] of nsmap) {
        if (i === 0)
          break;
        i -= 1;
      }

      this.log('Looking up NS: %s', ns);

      return this.lookupNS(rc, ns, zone);
    }

    const set = [];

    for (const [ns, zone] of nsmap) {
      const items = zones.get(zone);
      if (items && items.length > 0)
        set.push([ns, zone]);
    }

    if (set.length === 0)
      return null;

    const [ns, zone] = randomItem(set);
    const items = zones.get(zone);
    assert(items && items.length > 0);

    const auth = new Authority(zone, ns);

    for (const host of items)
      auth.add(host, DNS_PORT);

    return auth;
  }

  insert(rc) {
    if (!rc.hit) {
      const {qs, auth, res, chain} = rc;
      this.cache.insert(qs, auth.zone, res, chain);
    }
  }

  async handleTrust(rc) {
    assert(rc.chain);

    this.log('Verifying zone change to [%s]', rc.auth.zone);

    if (rc.hit) {
      if (!rc.res.ad) {
        this.log('Trust chain broken due to cache.');
        rc.chain = false;
        rc.ds = [];
        return;
      }
      rc.chain = true;
      return;
    }

    if (!rc.res.isDNSSEC()) {
      this.log('Trust chain broken due to lack of DO flag.');
      rc.chain = false;
      rc.ds = [];
      return;
    }

    this.log('Checking signatures...');

    if (!await this.checkSignatures(rc.res, rc.auth, rc.ds)) {
      this.log('Trust chain broken due to lack of child verification.');
      rc.chain = false;
      rc.ds = [];
    }
  }

  async handleAnswer(rc) {
    const [alias, chased] = isAlias(rc.res.answer, rc.qs);

    if (!alias) {
      this.insert(rc);
      return false;
    }

    if (rc.aliases.has(alias))
      throw new Error('Alias loop.');

    this.insert(rc);

    const auth = this.getAuthority();

    this.log('Found alias to: %s', alias);
    this.log('Alias changing zone: [%s->%s]', rc.auth.zone, auth.zone);

    rc.switchZone(auth);
    rc.follow(alias, chased);
    rc.hop();

    return true;
  }

  async handleAuthority(rc) {
    const {authority, additional} = rc.res;

    const hasNS = hasType(authority, types.NS);

    if (!hasNS) {
      if (rc.chain) {
        const nsec = extractSet(authority, '', types.NSEC3);

        if (!nsec3.verifyNoData(rc.qs, nsec)) {
          this.log('Trust chain broken due to missing NSEC coverage.');
          rc.chain = false;
          rc.ds = [];
        } else {
          this.log('Validated NSEC3 nodata.');
        }
      }

      this.insert(rc);

      return false;
    }

    const auth = await this.pickAuthority(rc, authority, additional);

    if (!auth) {
      this.insert(rc);
      return false;
    }

    const hasNSEC3 = hasType(authority, types.NSEC3);

    if (rc.chain && hasNSEC3) {
      const nsec = extractSet(authority, '', types.NSEC3);

      if (!nsec3.verifyDelegation(auth.zone, nsec)) {
        this.log('Trust chain broken due to bad delegation.');
        rc.chain = false;
        rc.ds = [];
      } else {
        this.log('Validated NSEC3 delegation.');
      }
    }

    this.insert(rc);

    this.log('Switching authority: %s', auth.name);
    this.log('Switching zone: [%s->%s]', rc.auth.zone, auth.zone);

    if (rc.chain) {
      // Grab DS records for the _next_ zone.
      rc.ds = extractSet(authority, auth.zone, types.DS);

      if (rc.ds.length === 0) {
        rc.chain = false;
        this.log('Trust chain broken due to zone change.');
      }
    }

    rc.switchZone(auth);
    rc.hop();

    return true;
  }

  async lookupNext(rc) {
    const [res, hit] = await this.ask(rc.qs, rc.auth);
    rc.res = res;
    rc.hit = hit;
  }

  async next(rc) {
    await this.lookupNext(rc);

    if (rc.chain)
      await this.handleTrust(rc);

    if (rc.chain && rc.res.code === codes.NXDOMAIN) {
      const nsec = extractSet(rc.res.authority, '', types.NSEC3);

      if (!nsec3.verifyNameError(rc.qs, nsec)) {
        this.log('Trust chain broken due to bad NX proof.');
        rc.chain = false;
        rc.ds = [];
      } else {
        this.log('Validated NSEC3 NX proof.');
      }
    }

    if (rc.res.isAnswer())
      return this.handleAnswer(rc);

    if (rc.res.isReferral())
      return this.handleAuthority(rc);

    return false;
  }

  async iterate(rc) {
    this.log('Querying %s (%s).', rc.qs.name, typeToString(rc.qs.type));

    this.log('Switching authority: %s', rc.auth.name);
    this.log('Switching zone: [%s]', rc.auth.zone);

    for (;;) {
      if (!await this.next(rc))
        break;
    }

    assert(rc.hops <= rc.maxReferrals);

    this.log(
      'Traversed zones: %s for %s (%s).',
      rc.zones.join(', '),
      rc.question.name,
      typeToString(rc.question.type)
    );

    if (rc.res.code === codes.NOERROR
        || rc.res.answer.length > 0
        || rc.res.authority.length > 0) {
      if (rc.chased.length > 0)
        rc.res.answer = rc.chased.concat(rc.res.answer);

      if (!rc.hit)
        this.cache.insert(rc.question, rc.ns.zone, rc.res, rc.chain);
    }

    return rc;
  }

  async follow(qs, hops) {
    assert(qs instanceof Question);
    assert(typeof hops === 'number');

    const ns = this.getAuthority();
    const rc = new ResolveContext(qs, ns, hops);

    rc.chain = this.dnssec;
    rc.maxReferrals = this.maxReferrals;

    return this.iterate(rc);
  }

  async resolve(qs) {
    assert(qs instanceof Question);

    if (!util.isName(qs.name))
      throw new Error('Invalid qname.');

    const rc = await this.follow(qs, 0);

    this.log('Finishing resolving %s (%s) (hops=%d).',
      qs.name, typeToString(qs.type), rc.hops);

    this.log('Cache usage: %s/%smb (items=%d).',
      (this.cache.size / 1024 / 1024).toFixed(2),
      (this.cache.maxSize / 1024 / 1024).toFixed(2),
      this.cache.map.size);

    return rc.toAnswer();
  }

  async lookup(name, type) {
    const qs = new Question(name, type);
    return this.resolve(qs);
  }

  async reverse(addr) {
    const name = encoding.reverse(addr);
    return this.lookup(name, types.PTR);
  }
}

/**
 * Resolve Context
 */

class ResolveContext {
  constructor(qs, ns, hops) {
    this.question = qs;
    this.ns = ns;
    this.hops = hops;
    this.qs = qs.clone();
    this.auth = ns;
    this.zones = [];
    this.aliases = new Set();
    this.chased = [];
    this.ds = [];
    this.chain = true;
    this.res = null;
    this.hit = false;
    this.maxReferrals = 30;
    this.switchZone(ns);
  }

  switchZone(auth) {
    this.auth = auth;
    this.zones.push(auth.zone);
    return this;
  }

  follow(alias, chased) {
    this.qs.name = alias;
    this.ds = [];
    this.aliases.add(alias);

    for (const rr of chased)
      this.chased.push(rr);

    return this;
  }

  hop() {
    if (this.hops >= this.maxReferrals)
      throw new Error('Maximum referrals exceeded.');

    this.hops += 1;
    return this;
  }

  toAnswer() {
    const res = new Message();

    res.id = this.res.id;
    res.opcode = this.res.opcode;
    res.code = this.res.code;
    res.qr = true;
    res.ra = true;
    res.ad = this.chain;
    res.question = [this.question];
    res.answer = this.res.answer.slice();
    res.authority = this.res.authority.slice();
    res.additional = this.res.additional.slice();
    res.edns = this.res.edns.clone();
    res.tsig = this.res.tsig;
    res.sig0 = this.res.sig0;
    res.size = this.res.size;
    res.malformed = this.res.malformed;
    res.trailing = this.res.trailing;

    return res;
  }
}

/*
 * Static
 */

RecursiveResolver.version = '0.0.0';
RecursiveResolver.native = 0;

/*
 * Helpers
 */

function collapseChain(name, records) {
  const chased = [];
  const map = new Map();
  const sigs = new Map();

  for (const rr of records) {
    const rd = rr.data;

    if (rr.type === types.CNAME) {
      map.set(rr.name.toLowerCase(), rr);
      continue;
    }

    if (rr.type === types.RRSIG) {
      if (rd.typeCovered === types.CNAME)
        sigs.set(rr.name.toLowerCase(), rr);
      continue;
    }
  }

  let qname = name.toLowerCase();
  let canonical = '';

  for (;;) {
    const cname = map.get(qname);
    const sig = sigs.get(qname);

    if (!cname)
      break;

    canonical = cname.data.target;
    qname = canonical.toLowerCase();

    chased.push(cname);

    if (sig)
      chased.push(sig);
  }

  return [canonical, chased];
}

function isAlias(answer, qs) {
  const rrs = filterSet(answer, types.RRSIG);

  if (rrs.length === 0)
    return ['', null];

  if (rrs.length > 1) {
    if (!hasAll(rrs, types.CNAME)
        || qs.type === types.CNAME) {
      return ['', null];
    }

    const [alias, chased] = collapseChain(qs.name, answer);

    return [alias, chased];
  }

  const rr = rrs[0];
  const rd = rr.data;

  switch (rr.type) {
    case types.CNAME: {
      if (qs.type === types.CNAME
          || !equal(qs.name, rr.name)) {
        return ['', null];
      }

      return [rd.target, answer];
    }

    case types.DNAME: {
      if (qs.type === types.DNAME)
        return ['', null];

      if (!isSubdomain(rr.name, qs.name))
        return ['', null];

      const bottom = qs.name.slice(0, -rr.name.length);
      const alias = bottom + rd.target;

      if (!util.isName(alias))
        throw new Error('Invalid DNAME.');

      return [alias, answer];
    }
  }

  return ['', null];
}

/*
 * Expose
 */

module.exports = RecursiveResolver;
