/*!
 * resolver.js - dns resolver for bns
 * Copyright (c) 2018, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bns
 */

'use strict';

const assert = require('assert');
const udp = require('budp');
const EventEmitter = require('events');
const wire = require('./wire');
const {Message} = wire;

const {
  Question,
  opcodes,
  classes,
  types,
  codes
} = wire;

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

const ROOT_SERVERS = [
  ['a', '198.41.0.4', '2001:503:ba3e::2:30'], // VeriSign, Inc.
  ['b', '199.9.14.201', '2001:500:200::b'], // USC (ISI)
  ['c', '192.33.4.12', '2001:500:2::c'], // Cogent Communications
  ['d', '199.7.91.13', '2001:500:2d::d'], // University of Maryland
  ['e', '192.203.230.10', '2001:500:a8::e'], // NASA (Ames Research Center)
  ['f', '192.5.5.241', '2001:500:2f::f'], // Internet Systems Consortium, Inc.
  ['g', '192.112.36.4', '2001:500:12::d0d'], // US Department of Defense (NIC)
  ['h', '198.97.190.53', '2001:500:1::53'], // US Army (Research Lab)
  ['i', '192.36.148.17', '2001:7fe::53'], // Netnod
  ['j', '192.58.128.30', '2001:503:c27::2:30'], // VeriSign, Inc.
  ['k', '193.0.14.129', '2001:7fd::1'], // RIPE NCC
  ['l', '199.7.83.42', '2001:500:9f::42'], // ICANN
  ['m', '202.12.27.33', '2001:dc3::35'] // WIDE Project
];

const MAX_DOMAIN_LENGTH = 256;
const MAX_REFERRALS = 10;
const YEAR68 = (1 << 31) >>> 0;

/**
 * DNSResolver
 * @extends EventEmitter
 */

class DNSResolver extends EventEmitter {
  constructor(options) {
    super();
    this.inet6 = false;
    if (options === 'udp6' || (options && options.type === 'udp6'))
      this.inet6 = true;
    this.socket = udp.createSocket(options);
    this.pending = new Map();
    this.id = 0;
    this.timer = null;
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

  async open(...args) {
    await this.socket.bind(...args);
    this.timer = setInterval(() => this.timeout(), 5000);
  }

  async close() {
    await this.socket.close();

    clearInterval(this.timer);
    this.timer = null;

    for (const item of this.pending.values())
      item.reject(new Error('Socket closed.'));

    this.pending.clear();
    this.id = 0;
  }

  async bind(...args) {
    return this.open(...args);
  }

  timeout() {
    const time = now();

    for (const [id, item] of this.pending) {
      if (time > item.time + 5 * 60) {
        this.pending.delete(id);
        item.reject(new Error('Request timed out.'));
      }
    }
  }

  handle(msg, rinfo) {
    const res = Message.fromRaw(msg);
    const item = this.pending.get(res.id);

    if (!item) {
      this.emit('error', new Error(`Unsolicited msg: ${res.id}.`));
      return;
    }

    this.pending.delete(res.id);

    item.resolve(res);
  }

  async exchange(req, port, host) {
    assert(req instanceof Message);
    assert(typeof port === 'number');
    assert(typeof host === 'string');

    req.id = this.id;
    req.response = false;

    this.id = (this.id + 1) & 0xffff;

    const msg = req.toRaw();

    this.socket.send(msg, 0, msg.length, port, host);

    return new Promise((resolve, reject) => {
      this.pending.set(req.id, {
        time: now(),
        resolve,
        reject
      });
    });
  }

  async query(q, port, host, rd) {
    assert(q instanceof Question);
    assert(typeof port === 'number');
    assert(typeof host === 'string');
    assert(typeof rd === 'boolean');

    const req = new Message();
    req.opcode = opcodes.QUERY;
    req.recursionDesired = rd;
    req.question.push(q);

    return this.exchange(req, port, host);
  }

  async lookup(name, type, port, host, rd) {
    const q = new Question(name, type);
    return this.query(q, port, host, rd);
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

  async resolve(q, port, host) {
    if (port == null)
      port = 53;

    if (host == null) {
      host = randomItem(this.inet6 ? OPENDNS_IPV6 : OPENDNS_IPV4);
      port = 53;
    }

    assert(typeof port === 'number');
    assert(typeof host === 'string');

    return this.query(q, port, host, true);
  }

  async lookup(name, type, port, host) {
    const q = new Question(name, type);
    return this.query(q, port, host);
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
  }

  randomAuthority() {
    const [ch, ipv4, ipv6] = randomItem(ROOT_SERVERS);
    return {
      name: `${ch}.root-servers.net.`,
      host: this.inet6 ? ipv6 : ipv4,
      port: 53,
      zone: '.'
    };
  }

  async ask(q, auth) {
    const {zone, port, host} = auth;
    const msg = this.cache.hit(q, zone);

    if (msg)
      return [true, msg];

    const res = await this.query(q, port, host, false);

    return [false, res];
  }

  async lookupNS(name) {
    const res = await this.lookup(name, types.A);

    if (res.code !== codes.NOERROR)
      throw new Error('Authority lookup failed.');

    if (res.answer.length === 0)
      throw new Error('No authority address.');

    const addrs = extractSet(res.answer, name, types.A);

    if (addrs.length === 0)
      throw new Error('No authority address.');

    const addr = randomItem(addrs);

    return {
      name,
      host: addr.data.address,
      port: 53,
      zone: '.'
    };
  }

  async pickAuthority(authority, additional) {
    const [zones, nsmap] = splitAuths(authority, additional, this.inet6);

    if (zones.size === 0) {
      if (nsmap.size === 0)
        return null;

      let i = random(nsmap.size);
      let ns, zone;

      for ([ns, zone] of nsmap) {
        if (--i === 0)
          break;
      }

      const auth = await this.lookupNS(ns);
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

    return {
      name: ns,
      host: randomItem(items),
      port: 53,
      zone
    };
  }

  // https://github.com/rolandshoemaker/solvere
  checkSignatures(rr, authority, pds) {
  }

  verifyNameError(q, nsec) {
  }

  verifyNoData(q, nsec) {
  }

  verifyDelegation(q, nsec) {
  }

  async resolve(question, auth, pds) {
    if (auth == null)
      auth = this.randomAuthority();

    if (pds == null)
      pds = [];

    assert(question instanceof Question);
    assert(typeof auth === 'object');
    assert(Array.isArray(pds));

    if (question.class !== classes.INET
        && question.class !== classes.ANY) {
      throw new Error('Unknown class.');
    }

    const q = question.clone();
    const aliases = new Set();
    const chased = [];

    for (let i = 0; i < MAX_REFERRALS; i++) {
      const isRoot = auth.zone === '.';
      const [hit, res] = await this.ask(q, auth);

      let ad = false;

      if (hit)
        ad = res.authenticatedData;

      if (!isRoot && pds.length > 0) {
        const err = this.checkSignatures(res, auth, pds);
        if (err)
          throw err;
        ad = true;
      }

      if (res.code !== codes.NOERROR) {
        if (res.code === codes.NAMEERROR) {
          const nsec = extractSet(res.authority, '', types.NSEC3);
          if (nsec.length !== 0) {
            const err = this.verifyNameError(q, nsec);
            if (err)
              throw err;
          }
        }
        return extractAnswer(res, question, ad);
      }

      if (res.answer.length > 0) {
        const [ok, cname, rr] = isAlias(res.answer, q);

        if (ok) {
          if (aliases.has(cname))
            throw new Error('Alias loop.');
          aliases.add(cname);
          auth = this.randomAuthority();
          q.name = cname;
          chased.push(rr);
          continue;
        }

        if (!hit)
          this.cache.insert(q, auth.zone, res, ad);

        if (chased.length > 0)
          res.answer = chased.concat(res.answer);

        return extractAnswer(res, question, ad);
      }

      const nsec = extractSet(res.authority, '', types.NSEC3);

      if (res.authority.length === 0 || nsec.length === res.authority.length) {
        if (nsec.length !== 0) {
          const err = this.verifyNoData(q, nsec);
          if (err)
            throw err;
        }
        return extractAnswer(new Message(), question, ad);
      }

      if (!hit)
        this.cache.insert(q, auth.zone, res, ad);

      auth = await this.pickAuthority(res.authority, res.additional);

      if (!auth) {
        if (chased.length > 0)
          res.answer = chased.concat(res.answer);
        return extractAnswer(res, question, ad);
      }

      if (nsec.length !== 0) {
        const err = this.verifyDelegation(auth.zone, nsec);
        if (err)
          throw err;
      } else if (pds.length > 0) {
        throw new Error('No NSEC records.');
      }

      if (isRoot || pds.length > 0) {
        pds = extractSet(res.authority, auth.zone, types.DS);
      } else if (!isRoot) {
        pds = [];
      }
    }

    throw new Error('Too many referrals.');
  }

  async lookup(name, type, auth, pds) {
    const q = new Question(name, type);
    return this.resolve(q, auth, pds);
  }
}

/**
 * Cache
 */

class Cache {
  constructor() {
    this.map = new Map();
  }

  prune() {
    for (const [id, item] of this.map) {
      if (item.expired())
        this.remove(id);
    }
    return this;
  }

  add(q, zone, msg, eternal = false) {
    const id = hashQuestion(q, zone);

    let ttl = 0;

    if (!eternal) {
      ttl = minTTL(msg);
      if (ttl === 0)
        return;
    }

    const item = this.map.get(id);

    if (item) {
      item.update(msg, ttl);
      return;
    }

    const entry = new CacheEntry();
    entry.answer = msg;
    entry.ttl = ttl;
    entry.modified = now();
    entry.eternal = eternal;

    this.map.set(id, entry);

    if (eternal)
      return;
  }

  get(q, zone) {
    const id = hashQuestion(q, zone);
    const entry = this.map.get(id);

    if (!entry)
      return null;

    return entry;
  }

  remove(id) {
    this.map.delete(id);
    return this;
  }

  answer(q, zone) {
    const id = hashQuestion(q, zone);
    const entry = this.map.get(id);

    if (!entry)
      return null;

    if (entry.expired()) {
      this.remove(id);
      return null;
    }

    return entry.answer;
  }

  hit(q, zone) {
    return null;
    const answer = this.answer(q, zone);

    if (!answer)
      return null;

    const res = new Message();
    res.code = codes.NOERROR;
    res.answer = answer.answer;
    res.authority = answer.authority;
    res.additional = answer.additional;
    res.authenticatedData = answer.authenticatedData;

    return res;
  }

  insert(q, zone, res, ad, eternal = false) {
    const msg = new Message();
    msg.authenticatedData = ad;
    msg.code = res.code;
    msg.answer = res.answer;
    msg.authority = res.authority;
    msg.additional = res.additional;
    return this.add(q, zone, msg, eternal);
  }
}

/**
 * CacheEntry
 */

class CacheEntry {
  constructor() {
    this.answer = null;
    this.ttl = 0;
    this.modified = 0;
    this.eternal = false;
  }

  update(answer, ttl) {
    this.answer = answer;
    this.ttl = ttl;
    this.modified = now();
    return this;
  }

  expired() {
    if (this.eternal)
      return false;

    return now() > this.modified + this.ttl;
  }
}

/*
 * Helpers
 */

function random(n) {
  return Math.floor(Math.random() * n);
}

function randomItem(items) {
  return items[random(items.length)];
}

function now() {
  return Math.floor(Date.now() / 1000);
}

function extractAnswer(m, q, ad) {
  const res = new Message();
  res.response = true;
  res.recursionAvailable = true;
  res.authenticatedData = ad;
  res.code = m.code;

  res.question = [q];
  res.answer = m.answer;
  res.authority = m.authority;
  res.additional = m.additional;

  return res;
}

function hasAll(records, type) {
  for (const rr of records) {
    if (rr.type !== type)
      return false;
  }
  return true;
}

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

function filterSet(records, ...types) {
  const map = new Set(types);
  const out = [];

  for (const rr of records) {
    if (!map.has(rr.type))
      out.push(rr);
  }

  return out;
}

function extractSet(records, name, ...types) {
  const map = new Set(types);
  const out = [];

  for (const rr of records) {
    if (map.has(rr.type)) {
      if (name !== '' && name !== rr.name)
        continue;
      out.push(rr);
    }
  }

  return out;
}

function isAlias(answer, q) {
  const filtered = filterSet(answer, types.RRSIG);

  if (filtered.length === 0)
    return [false, '', null];

  if (filtered.length > 1) {
    if (!hasAll(filtered, types.CNAME) || q.type === types.CNAME)
      return [false, '', null];
    const [sname, chased] = collapseChain(q.name, filtered);
    return [true, sname, chased];
  }

  const alias = filtered[0];

  switch (alias.type) {
    case types.CNAME: {
      if (q.type === types.CNAME || q.name !== alias.name)
        return [false, '', null];
      return [true, alias.data.target, alias];
    }
    case types.DNAME: {
      if (q.type === types.DNAME)
        return [false, '', null];

      if (!q.name.endsWith(alias.name))
        return [false, '', null];

      const sname = q.name.slice(0, -alias.name.length) + alias.data.target;

      if (sname.length > MAX_DOMAIN_LENGTH)
        throw new Error('DNAME too long.');

      return [true, sname, alias];
    }
  }

  return [false, '', null];
}

function splitAuths(authority, additional, inet6) {
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

    if (inet6) {
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

function minTTL(res) {
  const {answer, authority, additional} = res;
  const sections = [answer, authority, additional];

  let ttl = -1;

  for (const section of sections) {
    for (const rr of section) {
      if (ttl === -1 || rr.ttl < ttl)
        ttl = rr.ttl;

      if (rr.type === types.RRSIG) {
        const exp = rr.data.expiration;
        const n = now();
        const m = ((exp - n) / YEAR68) >>> 0;
        const t = exp + (m * YEAR68);
        const e = Math.floor((t - n) / 1000000000);

        if ((e >>> 0) === e && e < ttl)
          ttl = e;
      }
    }
  }

  if (ttl === -1)
    ttl = 0;

  return ttl;
}

function currentName(name, zone) {
  assert(name.length >= zone.length);
  assert(name.endsWith(zone));

  let len = zone.length;

  if (zone === '.')
    len = 0;

  let i = name.length - len;

  if (i === 0)
    return name;

  i -= 1;
  assert(name[i] === '.');

  i -= 1;

  for (; i >= 0; i--) {
    const ch = name[i];
    if (ch === '.')
      break;
  }

  return name.substring(i + 1);
}

function hashQuestion(q, zone) {
  // If q.name=mail.google.com. && zone=.
  // Then name=com.
  // If q.name=mail.google.com. && zone=com.
  // Then name=google.com.
  // If q.name=mail.google.com. && zone=google.com.
  // Then name=mail.google.com.
  const name = currentName(q.name, zone);
  if (name.length < q.name.length)
    return name;
  return `${name}${q.type}`;
}

/*
 * Expose
 */

exports.DNSResolver = DNSResolver;
exports.StubResolver = StubResolver;
exports.RecursiveResolver = RecursiveResolver;
