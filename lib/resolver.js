/*!
 * resolver.js - dns resolver for bns
 * Copyright (c) 2018, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bns
 *
 * Parts of this software are based on solvere:
 *   https://github.com/rolandshoemaker/solvere
 */

'use strict';

const assert = require('assert');
const EventEmitter = require('events');
const IP = require('binet');
const encoding = require('./encoding');
const wire = require('./wire');
const util = require('./util');
const dnssec = require('./dnssec');
const nsec3 = require('./nsec3');
const {Client} = require('./net');
const Heap = require('bheep');
const rootZone = require('./hints');

const {
  Message,
  Question,
  Record,
  Option,
  opcodes,
  classes,
  types,
  codes
} = wire;

const {
  extractSet,
  filterSet,
  hasAll,
  random,
  randomItem,
  isSubdomain,
  now
} = util;

/*
 * Constants
 */

const OPENDNS_IPV4 = [
  '208.67.222.222', // resolver1.opendns.com
  '208.67.220.220', // resolver2.opendns.com
  '208.67.222.220', // resolver3.opendns.com
  '208.67.220.222'  // resolver4.opendns.com
];

const OPENDNS_IPV6 = [
  '2620:0:ccc::2',
  '2620:0:ccd::2'
];

const GOOGLE_IPV4 = [
  '8.8.8.8',
  '8.8.4.4'
];

const GOOGLE_IPV6 = [
  '2001:4860:4860::8888',
  '2001:4860:4860::8844'
];

const MAX_DOMAIN_LENGTH = 256;
const MAX_REFERRALS = 20;
const MAX_RETRIES = 5;
const MAX_CACHE_SIZE = 20 << 20;

// Make eslint happy.
OPENDNS_IPV4;
OPENDNS_IPV6;

/**
 * DNSResolver
 * @extends EventEmitter
 */

class DNSResolver extends EventEmitter {
  constructor(options) {
    super();
    this.socket = new Client(options);
    this.inet6 = this.socket.inet6;
    this.pending = new Map();
    this.timer = null;
    this.edns = true;
    this.dnssec = true;
    this.init();
  }

  init() {
    this.socket.on('close', () => {
      this.emit('close');
    });

    this.socket.on('error', (err) => {
      this.emit('error', err);
    });

    this.socket.on('listening', () => {
      this.emit('listening');
    });

    this.socket.on('message', (msg, rinfo) => {
      try {
        this.handle(msg, rinfo);
      } catch (e) {
        this.emit('error', e);
      }
    });
  }

  log(...args) {
    this.emit('log', ...args);
  }

  async open(...args) {
    await this.socket.bind(...args);
    this.socket.setRecvBufferSize(4096);
    this.socket.setSendBufferSize(4096);
    this.timer = setInterval(() => this.timeout(), 5000);
  }

  async close() {
    await this.socket.close();

    clearInterval(this.timer);
    this.timer = null;

    for (const item of this.pending.values())
      item.reject(new Error('Socket closed.'));

    this.pending.clear();
  }

  async bind(...args) {
    return this.open(...args);
  }

  timeout() {
    const time = now();

    for (const item of this.pending.values()) {
      if (time > item.time + 10)
        this.retry(item, item.rinfo);
    }
  }

  error(msg) {
    this.emit('error', new Error(msg));
  }

  retry(item, rinfo, tcp) {
    if (tcp == null)
      tcp = rinfo.tcp;

    if (item.retries >= MAX_RETRIES) {
      this.pending.delete(item.id);
      item.reject(new Error('Request timed out.'));
      return;
    }

    const msg = item.req.encode();
    const {port, address} = item.rinfo;

    // Retry over TCP or UDP.
    this.socket.send(msg, 0, msg.length, port, address, tcp);

    // Update time.
    item.time = now();
    item.retries += 1;
  }

  handle(msg, rinfo) {
    const {port, address} = rinfo;

    // Close socket once we get an answer.
    if (rinfo.tcp)
      this.socket.drop(port, address);

    if (msg.length < 2) {
      this.error('Unsolicited msg.');
      return;
    }

    const id = msg.readUInt16BE(0, true);
    const item = this.pending.get(id);

    if (!item) {
      this.error(`Unsolicited msg: ${id}.`);
      return;
    }

    if (item.rinfo.address !== address
        || item.rinfo.port !== port) {
      this.error(`Unsolicited msg: ${id}.`);
      return;
    }

    let {req} = item;
    let res = null;

    try {
      res = Message.decode(msg);
    } catch (e) {
      this.pending.delete(id);
      item.reject(e);
      return;
    }

    if (!res.qr) {
      this.pending.delete(id);
      item.reject(new Error('Not a response.'));
      return;
    }

    if (!sameQuestion(req, res)) {
      this.pending.delete(id);
      item.reject(new Error('Format error.'));
      return;
    }

    if (res.tc) {
      if (rinfo.tcp) {
        this.pending.delete(id);
        item.reject(new Error('Truncated TCP msg.'));
        return;
      }

      // Retry over TCP.
      this.log('Retrying over TCP.');
      this.retry(item, rinfo, true);

      return;
    }

    if (res.opcode !== opcodes.QUERY) {
      this.pending.delete(id);
      item.reject(new Error('Unexpected opcode.'));
      return;
    }

    if ((res.code === codes.FORMATERROR
        || res.code === codes.NOTIMPLEMENTED
        || res.code === codes.SERVERFAILURE)
        && (!res.isEDNS0() && req.isEDNS0())) {
      // They don't like edns.
      req = req.clone();
      req.unsetEDNS0();
      item.req = req;
      this.retry(item, rinfo);
      return;
    }

    if (res.code === codes.FORMATERROR) {
      this.pending.delete(id);
      item.reject(new Error('Format error.'));
      return;
    }

    if (res.code === codes.SERVERFAILURE) {
      this.retry(item, rinfo);
      return;
    }

    if (isLame(req, res)) {
      this.pending.delete(id);
      item.reject(new Error('Server is lame.'));
      return;
    }

    this.pending.delete(id);

    item.resolve(res);
  }

  async exchange(req, port, host) {
    assert(req instanceof Message);
    assert(typeof port === 'number');
    assert(typeof host === 'string');
    assert(req.question.length > 0);

    req.id = (Math.random() * 0x10000) >>> 0;
    req.qr = false;

    const msg = req.encode();
    const tcp = msg.length >= 4096;

    this.socket.send(msg, 0, msg.length, port, host, tcp);

    return new Promise((resolve, reject) => {
      this.pending.set(req.id, {
        id: req.id,
        req,
        retries: 0,
        rinfo: {
          address: host,
          port,
          tcp
        },
        time: now(),
        resolve,
        reject
      });
    });
  }

  async query(qs, port, host, rd, opt) {
    assert(qs instanceof Question);
    assert(typeof port === 'number');
    assert(typeof host === 'string');
    assert(typeof rd === 'boolean');
    assert(!opt || (opt instanceof Option));

    const req = new Message();
    req.opcode = opcodes.QUERY;
    req.rd = rd;
    req.question.push(qs);

    if (this.edns) {
      req.setEDNS0(4096, this.dnssec);

      if (opt)
        req.setOption(opt);
    }

    return this.exchange(req, port, host);
  }

  async lookup(name, type, port, host, rd, opt) {
    const qs = new Question(name, type);
    return this.query(qs, port, host, rd, opt);
  }

  async reverse(addr, port, host, rd, opt) {
    const name = encoding.reverse(addr);
    return this.lookup(name, types.PTR, port, host, rd, opt);
  }
}

/**
 * StubResolver
 * @extends DNSResolver
 */

class StubResolver extends DNSResolver {
  constructor(options) {
    super(options);
  }

  async resolve(qs, port, host) {
    if (port == null)
      port = 53;

    if (host == null) {
      host = randomItem(this.inet6 ? GOOGLE_IPV6 : GOOGLE_IPV4);
      host = IP.normalize(host);
      port = 53;
    }

    assert(typeof port === 'number');
    assert(typeof host === 'string');

    return this.query(qs, port, host, true, null);
  }

  async lookup(name, type, port, host) {
    const qs = new Question(name, type);
    return this.resolve(qs, port, host);
  }

  async reverse(addr, port, host, rd) {
    const name = encoding.reverse(addr);
    return this.lookup(name, types.PTR, port, host);
  }
}

/**
 * Hints
 */

class Hints {
  constructor() {
    this.ns = [];
    this.inet4 = new Map();
    this.inet6 = new Map();
    this.anchors = [];
    this.port = 53;
    this.init();
  }

  init() {
    this.reset();
    this.ns.push('hints.local.');
    this.inet4.set('hints.local.', '127.0.0.1');
    this.inet6.set('hints.local.', '::1');
  }

  reset() {
    this.ns.length = 0;
    this.inet4.clear();
    this.inet6.clear();
    this.anchors.length = 0;
  }

  randomAuthority(inet6) {
    let name = null;
    let ip = null;

    assert(this.ns.length > 0);
    assert(inet6 || this.inet4.size > 0);
    assert(!inet6 || this.inet6.size > 0);

    while (!ip) {
      name = randomItem(this.ns);

      if (inet6) {
        ip = this.inet6.get(name);
        continue;
      }

      ip = this.inet4.get(name);
    }

    const auth = new Authority(name, ip);
    auth.port = this.port;
    return auth;
  }

  fromRecords(records) {
    this.reset();

    for (const rr of records) {
      const name = rr.name.toLowerCase();

      switch (rr.type) {
        case types.A: {
          this.inet4.set(name, rr.data.address);
          break;
        }
        case types.AAAA: {
          this.inet6.set(name, rr.data.address);
          break;
        }
      }
    }

    for (const rr of records) {
      const name = rr.name.toLowerCase();

      if (name !== '.')
        continue;

      switch (rr.type) {
        case types.NS: {
          const ns = rr.data.ns.toLowerCase();

          if (this.inet4.has(ns)
              || this.inet6.has(ns)) {
            this.ns.push(ns);
          }

          break;
        }
        case types.DS: {
          this.anchors.push(rr);
          break;
        }
      }
    }

    assert(this.ns.length > 0);
    assert(this.inet4.size > 0 || this.inet6.size > 0);

    return this;
  }

  static fromRecords(records) {
    return new this().fromRecords(records);
  }

  fromZone(text) {
    const records = wire.fromZone(text);
    return this.fromRecords(records);
  }

  static fromZone(text) {
    return new this().fromZone(text);
  }

  fromJSON(json) {
    assert(Array.isArray(json));

    const records = [];
    for (const item of json)
      records.push(Record.fromJSON(item));

    return this.fromRecords(records);
  }

  static fromJSON(json) {
    return new this().fromJSON(json);
  }
}

/**
 * RecursiveResolver
 * @extends DNSResolver
 */

class RecursiveResolver extends DNSResolver {
  constructor(options) {
    super(options);
    this.cache = new Cache();
    this.hints = Hints.fromZone(rootZone);
    this.nsec3 = false;
  }

  randomAuthority() {
    return this.hints.randomAuthority(this.inet6);
  }

  verify(qs, auth, opt, res) {
    return true;
  }

  async ask(qs, auth, opt) {
    const {zone, port, host} = auth;
    const cache = this.cache.hit(qs, zone);

    if (cache) {
      this.log('Cache hit for %s/%d.', qs.name, qs.type);
      return [cache, true];
    }

    if (auth.zone === '.') {
      const res = await this.query(qs, port, host, false, opt);

      if (!this.verify(qs, auth, opt, res))
        throw new Error('Invalid response.');

      return [res, false];
    }

    const res = await this.query(qs, port, host, false, null);

    return [res, false];
  }

  async findNS(rc, name, type) {
    const qs = new Question(name, type);
    const child = await this.follow(qs, rc.hops, rc.opt);
    const res = child.toAnswer();

    rc.hops = child.hops;

    if (res.code !== codes.NOERROR)
      throw new Error('Authority lookup failed.');

    const addrs = extractSet(res.answer, name, type);

    if (addrs.length === 0)
      throw new Error('No authority address.');

    const addr = randomItem(addrs);

    this.log('Picked nameserver: %s.', addr.data.address);

    return new Authority(name, addr.data.address);
  }

  async lookupNS(rc, name) {
    rc.hop();

    if (this.inet6) {
      this.log('Looking up IPv6 nameserver for %s...', name);
      try {
        return await this.findNS(rc, name, types.AAAA);
      } catch (e) {
        this.log('IPv6 nameserver lookup failed: %s', e.message);
      }
    }

    this.log('Looking up IPv4 nameserver for %s...', name);

    return this.findNS(rc, name, types.A);
  }

  async lookupDNSKEY(qs, auth, ds, opt) {
    const [res, hit] = await this.ask(qs, auth, opt);
    const keyMap = new Map();

    if (res.answer.length === 0
        || res.code !== codes.NOERROR) {
      return keyMap;
    }

    for (const rr of res.answer) {
      if (rr.type !== types.DNSKEY)
        continue;

      const rd = rr.data;

      if (rd.flags & dnssec.flags.REVOKE)
        continue;

      if (!(rd.flags & dnssec.flags.ZONE))
        continue;

      keyMap.set(rd.keyTag(), rr);
    }

    if (auth.zone === '.') {
      assert(ds.length === 0);
      ds = this.hints.anchors;
    }

    if (ds.length === 0)
      throw new Error('Invalid DNSKEY (DS absent).');

    if (!hit) {
      if (!dnssec.verifyDS(keyMap, ds))
        throw new Error('Invalid DNSKEY (DS mismatch).');

      if (!dnssec.verifyRRSIG(res, keyMap))
        throw new Error('Invalid RRSIG.');
    }

    if (!hit) {
      const eternal = auth.zone === '.';
      this.cache.insert(qs, auth.zone, res, true, eternal);
    }

    return keyMap;
  }

  async checkSignatures(msg, auth, ds, opt) {
    if (!this.dnssec)
      return true;

    const qs = new Question(auth.zone, types.DNSKEY);
    const keyMap = await this.lookupDNSKEY(qs, auth, ds, opt);

    if (keyMap.size === 0)
      throw new Error('No DNSKEY found.');

    if (!dnssec.verifyRRSIG(msg, keyMap))
      return false;

    this.log('Validated DNSSEC signatures.');

    return true;
  }

  splitAuths(authority, additional) {
    const zones = new Map();
    const nsmap = new Map();

    for (const rr of authority) {
      if (rr.type === types.NS)
        nsmap.set(rr.data.ns, rr.name);
    }

    for (const rr of additional) {
      const zone = nsmap.get(rr.name);

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

      const auth = await this.lookupNS(rc, ns);
      auth.zone = zone;

      return auth;
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

    const host = randomItem(items);

    return new Authority(ns, host, zone);
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

    if (!await this.checkSignatures(rc.res, rc.auth, rc.ds, rc.opt)) {
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

    const auth = this.randomAuthority();

    this.log('Found alias to: %s', alias);
    this.log('Alias changing zone: [%s->%s]', rc.auth.zone, auth.zone);

    rc.switchZone(auth);
    rc.follow(alias, chased);
    rc.hop();

    return true;
  }

  async handleAuthority(rc) {
    const nsec = extractSet(rc.res.authority, '', types.NSEC3);

    if (rc.res.authority.length === nsec.length) {
      if (this.nsec3 && rc.chain) {
        if (nsec.length === 0)
          throw new Error('No NSEC records.');

        if (!nsec3.verifyNoData(rc.qs, nsec))
          throw new Error('NSEC missing coverage.');
      }
      this.insert(rc);
      return false;
    }

    const {authority, additional} = rc.res;
    const auth = await this.pickAuthority(rc, authority, additional);

    if (!auth) {
      this.insert(rc);
      return false;
    }

    if (this.nsec3 && rc.chain && nsec.length > 0) {
      if (!nsec3.verifyDelegation(auth.zone, nsec))
        throw new Error('NSEC bad delegation.');
    }

    this.insert(rc);

    this.log('Switching authority: [%s] (%s)', auth.host, auth.name);
    this.log('Switching zone: [%s->%s]', rc.auth.zone, auth.zone);

    if (rc.chain) {
      // Grab DS records for the _next_ zone.
      rc.ds = extractSet(rc.res.authority, auth.zone, types.DS);
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
    const [res, hit] = await this.ask(rc.qs, rc.auth, rc.opt);
    rc.res = res;
    rc.hit = hit;
  }

  async next(rc) {
    await this.lookupNext(rc);

    if (rc.chain)
      await this.handleTrust(rc);

    if (rc.res.answer.length > 0
        && (rc.res.code === codes.NOERROR
        || rc.res.code === codes.YXDOMAIN
        || rc.res.code === codes.NXDOMAIN)) {
      return this.handleAnswer(rc);
    }

    if (rc.res.authority.length > 0
        && (rc.res.code === codes.NOERROR
        || rc.res.code === codes.YXDOMAIN)) {
      return this.handleAuthority(rc);
    }

    if (this.nsec3 && rc.chain && rc.res.code === codes.NXDOMAIN) {
      const nsec = extractSet(rc.res.authority, '', types.NSEC3);
      if (!nsec3.verifyNameError(rc.qs, nsec))
        throw new Error('NSEC missing coverage');
    }

    return false;
  }

  async iterate(rc) {
    this.log('Querying %s/%d.', rc.qs.name, rc.qs.type);

    for (;;) {
      if (!await this.next(rc))
        break;
    }

    assert(rc.hops <= MAX_REFERRALS);

    this.log('Traversed zones: %s for %s/%d.',
      rc.zones.join(', '), rc.question.name, rc.question.type);

    if (rc.res.answer.length > 0) {
      if (rc.chased.length > 0)
        rc.res.answer = rc.chased.concat(rc.res.answer);

      if (!rc.hit)
        this.cache.insert(rc.question, rc.ns.zone, rc.res, rc.chain);
    }

    return rc;
  }

  async follow(qs, hops, opt) {
    assert(qs instanceof Question);
    assert(typeof hops === 'number');
    assert(!opt || (opt instanceof Option));

    if (qs.class !== classes.INET
        && qs.class !== classes.ANY) {
      throw new Error('Unknown class.');
    }

    const ns = this.randomAuthority();
    const rc = new ResolveContext(qs, ns, hops, opt);
    rc.chain = this.dnssec;

    return this.iterate(rc);
  }

  async resolve(qs, opt) {
    const rc = await this.follow(qs, 0, opt);

    this.log('Finishing resolving %s/%d (hops=%d).', qs.name, qs.type, rc.hops);

    return rc.toAnswer();
  }

  async lookup(name, type, opt) {
    const qs = new Question(name, type);
    return this.resolve(qs, opt);
  }

  async reverse(addr, opt) {
    const name = encoding.reverse(addr);
    return this.lookup(name, types.PTR, opt);
  }
}

/**
 * Authority
 */

class Authority {
  constructor(name, host, zone) {
    this.name = name || '.';
    this.host = host || '0.0.0.0';
    this.port = 53;
    this.zone = zone || '.';
  }
}

/**
 * Resolve Context
 */

class ResolveContext {
  constructor(qs, ns, hops, opt) {
    this.question = qs;
    this.ns = ns;
    this.hops = hops;
    this.opt = opt || null;
    this.qs = qs.clone();
    this.auth = ns;
    this.zones = [];
    this.aliases = new Set();
    this.chased = [];
    this.ds = [];
    this.chain = true;
    this.res = null;
    this.hit = false;
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
    if (this.hops >= MAX_REFERRALS)
      throw new Error('Maximum referrals exceeded.');

    this.hops += 1;
    return this;
  }

  toAnswer() {
    const res = new Message();

    res.qr = true;
    res.opcode = this.res.opcode;
    res.ra = true;
    res.ad = this.chain;
    res.code = this.res.code;
    res.question = [this.question];
    res.answer = this.res.answer.slice();
    res.authority = this.res.authority.slice();
    res.additional = this.res.additional.slice();

    return res;
  }
}

/**
 * Cache
 */

class Cache {
  constructor() {
    this.map = new Map();
    this.queue = new Heap((a, b) => a[1] - b[1]);
    this.size = 0;
  }

  get(id) {
    return this.map.get(id) || null;
  }

  has(id) {
    return this.map.has(id);
  }

  remove(id) {
    this.map.delete(id);
    return this;
  }

  hash(qs, zone) {
    return `${qs.name.toLowerCase()}${qs.type}${zone.toLowerCase()}`;
  }

  prune() {
    while (this.size > MAX_CACHE_SIZE) {
      const [id, deadline] = this.queue.shift();
      const entry = this.get(id);

      if (entry && entry.deadline === deadline) {
        this.size -= entry.usage();
        this.size -= id.length * 2 + 20;
        this.remove(id);
      } else {
        this.size -= id.length * 2 + 20;
      }
    }

    return this;
  }

  insert(qs, zone, msg, ad, eternal = false) {
    const id = this.hash(qs, zone);
    const ttl = msg.minTTL();

    if (ttl === 0)
      return this;

    const item = this.get(id);

    if (item) {
      if (item.eternal)
        return this;

      const raw = msg.encode();

      this.size -= item.usage();

      item.msg = raw;
      item.setAD(ad);
      item.deadline = now() + ttl;

      this.size += item.usage();
      this.queue.insert([id, item.deadline]);
      this.size += id.length * 2 + 20;
      this.prune();

      return this;
    }

    const raw = msg.encode();
    const entry = new CacheEntry(raw);

    entry.setAD(ad);

    this.map.set(id, entry);
    this.size += entry.usage();

    if (eternal) {
      entry.eternal = true;
      entry.deadline = -1 >>> 0;
    } else {
      entry.deadline = now() + ttl;
      this.queue.insert([id, entry.deadline]);
      this.size += id.length * 2 + 20;
      this.prune();
    }

    return this;
  }

  hit(qs, zone) {
    const id = this.hash(qs, zone);
    const entry = this.map.get(id);

    if (!entry)
      return null;

    if (entry.expired()) {
      this.size -= entry.usage();
      this.remove(id);
      return null;
    }

    return Message.decode(entry.msg);
  }
}

/**
 * CacheEntry
 */

class CacheEntry {
  constructor(msg) {
    assert(Buffer.isBuffer(msg));
    this.msg = msg;
    this.deadline = 0;
    this.eternal = false;
  }

  usage() {
    return this.msg.length + 80 + 8 + 8;
  }

  setAD(ad) {
    let bits = this.msg.readUInt16BE(2, true);

    if (ad)
      bits |= wire.flags.AD;
    else
      bits &= ~wire.flags.AD;

    this.msg.writeUInt16BE(bits, 2, true);
  }

  expired() {
    if (this.eternal)
      return false;

    return now() > this.deadline;
  }
}

/*
 * Helpers
 */

function collapseChain(qname, records) {
  const chased = [];
  const map = new Map();

  for (const rr of records) {
    if (rr.type === types.CNAME)
      map.set(rr.name, rr);
  }

  let canonical = '';

  for (;;) {
    const cname = map.get(qname);

    if (!cname)
      break;

    canonical = cname.data.target;
    qname = canonical;
    chased.push(cname);
  }

  return [canonical, chased];
}

function isAlias(answer, qs) {
  const rrs = filterSet(answer, types.RRSIG);

  if (rrs.length === 0)
    return ['', null];

  if (rrs.length > 1) {
    if (!hasAll(rrs, types.CNAME) || qs.type === types.CNAME)
      return ['', null];
    const [sname, chased] = collapseChain(qs.name, rrs);
    return [sname, chased];
  }

  const rr = rrs[0];
  const rd = rr.data;

  switch (rr.type) {
    case types.CNAME: {
      if (qs.type === types.CNAME || qs.name !== rr.name)
        return ['', null];
      return [rd.target, rrs];
    }
    case types.DNAME: {
      if (qs.type === types.DNAME)
        return ['', null];

      if (!isSubdomain(rr.name, qs.name))
        return ['', null];

      const bottom = qs.name.slice(0, -rr.name.length);
      const sname = bottom + rd.target;

      if (sname.length > MAX_DOMAIN_LENGTH)
        throw new Error('DNAME too long.');

      return [sname, rrs];
    }
  }

  return ['', null];
}

function sameQuestion(req, res) {
  switch (res.code) {
    case codes.NOTIMPLEMENTED:
    case codes.FORMATERROR:
    case codes.NXRRSET:
      if (res.question.length === 0)
        break;
    case codes.BADCOOKIE:
    case codes.NOERROR:
    case codes.NXDOMAIN:
    case codes.YXDOMAIN:
    case codes.REFUSED:
    case codes.SERVERFAILURE:
    default:
      if (res.question.length === 0) {
        if (res.tc)
          return true;
        return false;
      }

      if (res.question.length > 1)
        return false;

      if (!res.question[0].equals(req.question[0]))
        return false;

      break;
  }

  return true;
}

function isLame(req, res) {
  const name = req.question[0].name;

  if (res.code !== codes.NOERROR
      && res.code !== codes.YXDOMAIN
      && res.code !== codes.NXDOMAIN) {
    return false;
  }

  if (res.answer.length !== 0)
    return false;

  for (const rr of res.authority) {
    if (rr.type !== types.NS)
      continue;

    if (util.equal(rr.name, name))
      continue;

    if (util.isSubdomain(rr.name, name))
      continue;

    return true;
  }

  return false;
}

/*
 * Expose
 */

exports.Cache = Cache;
exports.Hints = Hints;
exports.Authority = Authority;
exports.DNSResolver = DNSResolver;
exports.StubResolver = StubResolver;
exports.RecursiveResolver = RecursiveResolver;
