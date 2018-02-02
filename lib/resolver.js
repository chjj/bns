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
const encoding = require('./encoding');
const wire = require('./wire');
const util = require('./util');
const dnssec = require('./dnssec');
const nsec3 = require('./nsec3');
const {Client} = require('./net');

const {
  Message,
  Question,
  Record,
  DNSKEYRecord,
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

const ROOT_KEYS = [
  {
    flags: 257,
    protocol: 3,
    algorithm: 8,
    publicKey: ''
      + 'AwEAAaz/tAm8yTn4Mfeh5eyI96WSVexTBAvkMgJzkKTOiW1vkIbzxeF3'
      + '+/4RgWOq7HrxRixHlFlExOLAJr5emLvN7SWXgnLh4+B5xQlNVz8Og8kv'
      + 'ArMtNROxVQuCaSnIDdD5LKyWbRd2n9WGe2R8PzgCmr3EgVLrjyBxWezF'
      + '0jLHwVN8efS3rCj/EWgvIWgb9tarpVUDK/b58Da+sqqls3eNbuv7pr+e'
      + 'oZG+SrDK6nWeL3c6H5Apxz7LjVc1uTIdsIXxuOLYA4/ilBmSVIzuDWfd'
      + 'RUfhHdY6+cn8HFRm+2hM8AnXGXws9555KrUB5qihylGa8subX2Nn6UwN'
      + 'R1AkUTV74bU='
  },
  {
    flags: 256,
    protocol: 3,
    algorithm: 8,
    publicKey: ''
      + 'AwEAAaDJd0KOMYGCEF0/cftC2hrFtz5GSn1HOiaxEp053AfbxQ3pT8BE'
      + 'tahPiUkCo1Qx4PECJ23YwaFhfWWjapr6AFxhD8klfZGp95ickoRlm91Z'
      + 'zXX/mcfn9vlUpZK2M8qjljNMzZJSopFY+cxRvib2Irb6YeP2a0vppaLn'
      + 'vR4BeOyEkQolLqvVHW7UqDFiP/CM15BWBsAIdbyo8L1h3OeP63TaYIrW'
      + 'ttjGBILeZinSaJ39amiVs8t00RjTaKVo3vY2k6dje1Rh1ELqjNj8+cKA'
      + '8iWC3VU7ApkyuGDy631RDILa6wCgcBVCzfFfOthQILxQra88tNWzCVor'
      + 'yQ89f1WjBJc='
  },
  {
    flags: 257,
    protocol: 3,
    algorithm: 8,
    publicKey: ''
      + 'AwEAAagAIKlVZrpC6Ia7gEzahOR+9W29euxhJhVVLOyQbSEW0O8gcCjF'
      + 'FVQUTf6v58fLjwBd0YI0EzrAcQqBGCzh/RStIoO8g0NfnfL2MTJRkxoX'
      + 'bfDaUeVPQuYEhg37NZWAJQ9VnMVDxP/VHL496M/QZxkjf5/Efucp2gaD'
      + 'X6RS6CXpoY68LsvPVjR0ZSwzz1apAzvN9dlzEheX7ICJBBtuA6G3LQpz'
      + 'W5hOA2hzCTMjJPJ8LbqF6dsV6DoBQzgul0sGIcGOYl7OyQdXfZ57relS'
      + 'Qageu+ipAdTTJ25AsRTAoub8ONGcLmqrAmRLKBP1dfwhYB4N7knNnulq'
      + 'QxA+Uk1ihz0='
  }
];

const MAX_DOMAIN_LENGTH = 256;
const MAX_REFERRALS = 10;

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
    this.socket = new Client(options);
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

    if (res.truncated) {
      if (rinfo.tcp) {
        this.emit('error', new Error(`Truncated TCP msg: ${res.id}.`));
        return;
      }

      const {msg} = item;
      const {port, address} = rinfo;

      // Retry over TCP.
      this.socket.send(msg, 0, msg.length, port, address, true);

      // Update time.
      item.time = now();

      return;
    }

    // Close socket once we get an answer.
    if (rinfo.tcp) {
      const {port, address} = rinfo;
      this.socket.drop(port, address);
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
    const tcp = msg.length >= 4096;

    this.socket.send(msg, 0, msg.length, port, host, tcp);

    return new Promise((resolve, reject) => {
      this.pending.set(req.id, {
        msg,
        time: now(),
        resolve,
        reject
      });
    });
  }

  async query(qs, port, host, rd) {
    assert(qs instanceof Question);
    assert(typeof port === 'number');
    assert(typeof host === 'string');
    assert(typeof rd === 'boolean');

    const req = new Message();
    req.opcode = opcodes.QUERY;
    req.recursionDesired = rd;
    req.question.push(qs);
    req.setEDNS0(4096, true);

    return this.exchange(req, port, host);
  }

  async lookup(name, type, port, host, rd) {
    const qs = new Question(name, type);
    return this.query(qs, port, host, rd);
  }

  async reverse(addr, port, host, rd) {
    const name = encoding.reverse(addr);
    return this.lookup(name, types.PTR, port, host, rd);
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
      host = randomItem(this.inet6 ? OPENDNS_IPV6 : OPENDNS_IPV4);
      port = 53;
    }

    assert(typeof port === 'number');
    assert(typeof host === 'string');

    return this.query(qs, port, host, true);
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
 * RecursiveResolver
 * @extends DNSResolver
 */

class RecursiveResolver extends DNSResolver {
  constructor(options) {
    super(options);
    this.cache = new Cache();
    this.ds = [];
    this._init();
  }

  _init() {
    const msg = new Message();
    const qs = new Question('.', types.DNSKEY);

    msg.question.push(qs);

    for (const data of ROOT_KEYS) {
      const rd = new DNSKEYRecord();
      rd.flags = data.flags;
      rd.protocol = data.protocol;
      rd.algorithm = data.algorithm;
      rd.publicKey = Buffer.from(data.publicKey, 'base64');

      const rr = new Record();
      rr.name = '.';
      rr.type = types.DNSKEY;
      rr.ttl = 172800;
      rr.data = rd;

      msg.answer.push(rr);
    }

    for (const rr of msg.answer) {
      const ds = dnssec.createDS(rr, dnssec.hashes.SHA256);
      this.ds.push(ds);
    }

    this.cache.insert(qs, '.', msg, true, true);
  }

  randomAuthority() {
    const [ch, ipv4, ipv6] = randomItem(ROOT_SERVERS);
    return {
      name: `${ch}.root-servers.net.`,
      host: this.inet6 ? ipv6 : ipv4,
      port: 53,
      zone: '.',
      holdsTrust: true
    };
  }

  async ask(qs, auth) {
    const {zone, port, host} = auth;
    const msg = this.cache.hit(qs, zone);

    if (msg)
      return [true, msg];

    const res = await this.query(qs, port, host, false);

    return [false, res];
  }

  async lookupNS(name) {
    const A = this.inet6 ? types.AAAA : types.A;
    const res = await this.lookup(name, A);

    if (res.code !== codes.NOERROR)
      throw new Error('Authority lookup failed.');

    if (res.answer.length === 0)
      throw new Error('No authority address.');

    const addrs = extractSet(res.answer, name, A);

    if (addrs.length === 0)
      throw new Error('No authority address.');

    const addr = randomItem(addrs);

    return {
      name,
      host: addr.data.address,
      port: 53,
      zone: '.',
      holdsTrust: res.authenticatedData
    };
  }

  async lookupDNSKEY(auth) {
    const qs = new Question(auth.zone, types.DNSKEY);
    const [hit, res] = await this.ask(qs, auth);

    if (res.answer.length === 0 || res.code !== codes.NOERROR)
      throw new Error('No DNSKEY.');

    const keyMap = new Map();

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

    if (keyMap.size === 0)
      throw new Error('No DNSKEY.');

    if (auth.zone !== '.') {
      if (!dnssec.verifyRRSIG(res, keyMap))
        throw new Error('Invalid RRSIG.');
    }

    return [qs, hit, res, keyMap];
  }

  async checkSignatures(msg, auth, ds) {
    const [qs, hit, res, keyMap] = await this.lookupDNSKEY(auth);

    if (!dnssec.verifyDS(keyMap, ds))
      throw new Error('Invalid DS.');

    if (!dnssec.verifyRRSIG(msg, keyMap))
      throw new Error('Invalid RRSIG.');

    if (!hit)
      this.cache.insert(qs, auth.zone, res, true);
  }

  async pickAuthority(authority, additional) {
    const [zones, nsmap] = splitAuths(authority, additional, this.inet6);

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
      zone,
      holdsTrust: true
    };
  }

  async resolve(question, auth, ds) {
    if (auth == null)
      auth = this.randomAuthority();

    if (ds == null) {
      assert(auth.zone === '.');
      ds = this.ds;
    }

    assert(question instanceof Question);
    assert(typeof auth === 'object');
    assert(Array.isArray(ds));

    if (question.class !== classes.INET
        && question.class !== classes.ANY) {
      throw new Error('Unknown class.');
    }

    const qs = question.clone();
    const aliases = new Set();
    const chased = [];

    let ad = false;

    for (let i = 0; i < MAX_REFERRALS; i++) {
      const [hit, res] = await this.ask(qs, auth);

      if (ds.length > 0) {
        console.log(auth.zone);
        util.dir(ds);
        if (hit) {
          if (!res.authenticatedData)
            throw new Error('Invalid cached signature.');
        } else {
          await this.checkSignatures(res, auth, ds);
        }
        ad = true;
      }

      if (res.code !== codes.NOERROR) {
        if (res.code === codes.NAMEERROR) {
          const nsec = extractSet(res.authority, '', types.NSEC3);
          if (nsec.length !== 0) {
            if (!nsec3.verifyNameError(qs, nsec))
              throw new Error('NSEC missing coverage');
          }
        }
        return extractAnswer(res, question, ad);
      }

      if (res.answer.length > 0) {
        const [ok, cname, rr] = isAlias(res.answer, qs);

        if (ok) {
          if (aliases.has(cname))
            throw new Error('Alias loop.');

          aliases.add(cname);

          auth = this.randomAuthority();
          ds = this.ds;
          ad = false;

          qs.name = cname;
          chased.push(rr);

          continue;
        }

        if (!hit)
          this.cache.insert(qs, auth.zone, res, ad);

        if (chased.length > 0)
          res.answer = chased.concat(res.answer);

        return extractAnswer(res, question, ad);
      }

      const nsec = extractSet(res.authority, '', types.NSEC3);

      if (res.authority.length === 0 || nsec.length === res.authority.length) {
        if (nsec.length !== 0) {
          if (!nsec3.verifyNoData(qs, nsec))
            throw new Error('NSEC missing coverage.');
        }
        return extractAnswer(new Message(), question, ad);
      }

      // if (nsec.length === 0) {
      //   if (auth.zone !== '.' && ds.length > 0)
      //     throw new Error('No NSEC records.');
      // }

      // if (!hit)
      //   this.cache.insert(qs, auth.zone, res, ad);

      auth = await this.pickAuthority(res.authority, res.additional);

      if (!auth) {
        if (chased.length > 0)
          res.answer = chased.concat(res.answer);
        return extractAnswer(res, question, ad);
      }

      if (!auth.holdsTrust)
        ad = false;

      if (nsec.length > 0) {
        if (!nsec3.verifyDelegation(auth.zone, nsec))
          throw new Error('NSEC bad delegation.');
      }

      if (ds.length > 0)
        ds = extractSet(res.authority, auth.zone, types.DS);
      else
        ad = false;
    }

    throw new Error('Too many referrals.');
  }

  async lookup(name, type, auth, ds) {
    const qs = new Question(name, type);
    return this.resolve(qs, auth, ds);
  }

  async reverse(addr, auth, ds) {
    const name = encoding.reverse(addr);
    return this.lookup(name, types.PTR, auth, ds);
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

  add(qs, zone, msg, eternal = false) {
    const id = hashQuestion(qs, zone);

    let ttl = 0;

    if (!eternal) {
      ttl = msg.minTTL();
      if (ttl === 0)
        return this;
    }

    const item = this.map.get(id);

    if (item) {
      item.update(msg, ttl);
      return this;
    }

    const entry = new CacheEntry();
    entry.answer = msg;
    entry.ttl = ttl;
    entry.modified = now();
    entry.eternal = eternal;

    this.map.set(id, entry);

    if (eternal)
      return this;

    return this;
  }

  get(qs, zone) {
    const id = hashQuestion(qs, zone);
    const entry = this.map.get(id);

    if (!entry)
      return null;

    return entry;
  }

  remove(id) {
    this.map.delete(id);
    return this;
  }

  answer(qs, zone) {
    const id = hashQuestion(qs, zone);
    const entry = this.map.get(id);

    if (!entry)
      return null;

    if (entry.expired()) {
      this.remove(id);
      return null;
    }

    return entry.answer;
  }

  hit(qs, zone) {
    const answer = this.answer(qs, zone);

    if (!answer)
      return null;

    const res = new Message();
    res.authenticatedData = answer.authenticatedData;
    res.code = codes.NOERROR;
    res.answer = answer.answer;
    res.authority = answer.authority;
    res.additional = answer.additional;

    return res;
  }

  insert(qs, zone, res, ad, eternal = false) {
    const msg = new Message();
    msg.authenticatedData = ad;
    msg.code = res.code;
    msg.answer = res.answer;
    msg.authority = res.authority;
    msg.additional = res.additional;
    return this.add(qs, zone, msg, eternal);
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

function extractAnswer(m, qs, ad) {
  const res = new Message();

  res.response = true;
  res.recursionAvailable = true;
  res.authenticatedData = ad;
  res.code = m.code;

  res.question = [qs];
  res.answer = m.answer;
  res.authority = m.authority;
  res.additional = m.additional;

  return res;
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

function isAlias(answer, qs) {
  const filtered = filterSet(answer, types.RRSIG);

  if (filtered.length === 0)
    return [false, '', null];

  if (filtered.length > 1) {
    if (!hasAll(filtered, types.CNAME) || qs.type === types.CNAME)
      return [false, '', null];
    const [sname, chased] = collapseChain(qs.name, filtered);
    return [true, sname, chased];
  }

  const alias = filtered[0];

  switch (alias.type) {
    case types.CNAME: {
      if (qs.type === types.CNAME || qs.name !== alias.name)
        return [false, '', null];
      return [true, alias.data.target, alias];
    }
    case types.DNAME: {
      if (qs.type === types.DNAME)
        return [false, '', null];

      if (!qs.name.endsWith(alias.name))
        return [false, '', null];

      const sname = qs.name.slice(0, -alias.name.length) + alias.data.target;

      if (sname.length > MAX_DOMAIN_LENGTH)
        throw new Error('DNAME too long.');

      return [true, sname, alias];
    }
  }

  return [false, '', null];
}

function splitAuths(authority, additional, inet6) {
  const A = inet6 ? types.AAAA : types.A;
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

    if (rr.type !== A)
      continue;

    let items = zones.get(zone);

    if (!items) {
      items = [];
      zones.set(zone, items);
    }

    items.push(rr.data.address);
  }

  return [zones, nsmap];
}

function hashQuestion(qs, zone) {
  return `${qs.name}${qs.type}`;
}

/*
 * Expose
 */

exports.DNSResolver = DNSResolver;
exports.StubResolver = StubResolver;
exports.RecursiveResolver = RecursiveResolver;
