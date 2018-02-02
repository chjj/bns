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

    if (res.tc) {
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
    req.qr = false;

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
    req.rd = rd;
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

    // this.cache.insert(qs, '.', msg, true, true);
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

  async ask(qs, auth) {
    const {zone, port, host} = auth;
    const msg = this.cache.hit(qs, zone);

    if (msg) {
      this.log('Cache hit for %s/%d.', qs.name, qs.type);
      return [true, msg];
    }

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
      zone: '.'
    };
  }

  async askDNSKEY(qs, auth) {
    const [hit, res] = await this.ask(qs, auth);
    const keyMap = new Map();

    if (res.answer.length === 0 || res.code !== codes.NOERROR)
      return [hit, res, keyMap];

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

    return [hit, res, keyMap];
  }

  async checkSignatures(msg, auth, ds) {
    const qs = new Question(auth.zone, types.DNSKEY);
    const [hit, res, keyMap] = await this.askDNSKEY(qs, auth);

    if (keyMap.size === 0)
      throw new Error('No DNSKEY found.');

    // Keys must match all DS records.
    if (!dnssec.verifyDS(keyMap, ds))
      throw new Error('Invalid DNSKEY (DS mismatch).');

    if (!dnssec.verifyRRSIG(res, keyMap))
      throw new Error('Invalid RRSIG.');

    if (!dnssec.verifyRRSIG(msg, keyMap))
      return false;

    this.log('Validated.');

    if (!hit) {
      const eternal = auth.zone === '.';
      this.cache.insert(qs, auth.zone, res, true, eternal);
    }

    return true;
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

      this.log('Looking up NS: %s', ns);

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

  async verify(hit, res, auth, ds) {
    if (hit) {
      if (!res.ad) {
        this.log('Trust chain broken due to cache.');
        return false;
      }
      return true;
    }

    if (!res.isDNSSEC()) {
      this.log('Trust chain broken due to lack of DO flag.');
      return false;
    }

    this.log('Checking signatures...');

    if (!await this.checkSignatures(res, auth, ds)) {
      this.log('Trust chain broken due to lack of child verification.');
      return false;
    }

    return true;
  }

  async resolve(qs, ns) {
    if (ns == null)
      ns = this.randomAuthority();

    return this._resolve(qs, ns, null);
  }

  async _resolve(question, ns, root) {
    assert(question instanceof Question);
    assert(ns && typeof ns === 'object');
    assert(root == null || (root instanceof Message));

    if (question.class !== classes.INET
        && question.class !== classes.ANY) {
      throw new Error('Unknown class.');
    }

    this.log('Querying %s/%d.', question.name, question.type);

    const zones = [ns.zone];
    const qs = question.clone();
    const aliases = new Set();
    const chased = [];

    let auth = ns;
    let parent = '~';

    let ds = [];
    let chain = true;
    let i = root ? 0 : 1;
    let hit = root ? true : false;
    let res = root;

    for (; i < MAX_REFERRALS; i++) {
      if (i > 0) {
        [hit, res] = await this.ask(qs, auth);

        if (chain) {
          this.log('Verifying zone change: [%s->%s]', parent, auth.zone);
          chain = await this.verify(hit, res, auth, ds);
        }
      }

      if (res.code !== codes.NOERROR) {
        if (res.code === codes.NAMEERROR) {
          const nsec = extractSet(res.authority, '', types.NSEC3);
          if (nsec.length !== 0) {
            if (!nsec3.verifyNameError(qs, nsec))
              throw new Error('NSEC missing coverage');
          }
        }
        break;
      }

      if (res.answer.length > 0) {
        const [alias, rrs] = isAlias(res.answer, qs);

        if (alias) {
          if (aliases.has(alias))
            throw new Error('Alias loop.');

          aliases.add(alias);

          if (!hit)
            this.cache.insert(qs, auth.zone, res, chain);

          parent = auth.zone;
          auth = this.randomAuthority();
          zones.push(auth.zone);
          ds = [];

          this.log('Found alias to: %s', alias);
          this.log('Alias changed zone: [%s->%s]', parent, auth.zone);

          qs.name = alias;

          for (const rr of rrs)
            chased.push(rr);

          continue;
        }

        if (!hit)
          this.cache.insert(qs, auth.zone, res, chain);

        break;
      }

      const nsec = extractSet(res.authority, '', types.NSEC3);

      if (nsec.length === res.authority.length) {
        if (nsec.length !== 0) {
          if (!nsec3.verifyNoData(qs, nsec))
            throw new Error('NSEC missing coverage.');
        }
        if (!hit)
          this.cache.insert(qs, auth.zone, res, chain);
        break;
      }

      if (res.aa && chain) {
        if (nsec.length === 0)
          throw new Error('No NSEC records.');
      }

      parent = auth.zone;
      auth = await this.pickAuthority(res.authority, res.additional);

      if (!auth) {
        if (!hit)
          this.cache.insert(qs, parent, res, chain);
        break;
      }

      zones.push(auth.zone);

      this.log('Switching authority: [%s] (%s)', auth.host, auth.name);
      this.log('Switching zone: [%s->%s]', parent, auth.zone);

      if (nsec.length > 0) {
        if (!nsec3.verifyDelegation(auth.zone, nsec))
          throw new Error('NSEC bad delegation.');
      }

      if (!hit)
        this.cache.insert(qs, parent, res, chain);

      if (chain) {
        ds = extractSet(res.authority, auth.zone, types.DS);
        chain = ds.length > 0;
        if (!chain)
          this.log('Trust chain broken due to zone change.');
      }
    }

    this.log('Traversed zones: %s for %s/%d.',
      zones.join(', '), question.name, question.type);

    if (i === MAX_REFERRALS)
      throw new Error('Too many referrals.');

    if (res.answer.length > 0) {
      if (chased.length > 0)
        res.answer = chased.concat(res.answer);

      if (!hit && !root)
        this.cache.insert(question, ns.zone, res, chain);
    }

    return extractAnswer(res, question, chain);
  }

  async lookup(name, type, ns) {
    const qs = new Question(name, type);
    return this.resolve(qs, ns);
  }

  async reverse(addr, ns) {
    const name = encoding.reverse(addr);
    return this.lookup(name, types.PTR, ns);
  }

  async resolveRoot(qs, root, ns) {
    if (ns == null)
      ns = this.randomAuthority();

    assert(qs instanceof Question);
    assert(root instanceof Message);
    assert(ns && ns.zone === '.');

    root = root.clone();
    root.ad = true;
    root.aa = false;
    root.additional = root.additional.slice();
    root.setEDNS0(4096, true);

    return this._resolve(qs, ns, root);
  }

  async lookupRoot(name, type, root, ns) {
    const qs = new Question(name, type);
    return this.resolveRoot(qs, root, ns);
  }
}

/**
 * Cache
 */

class Cache {
  constructor() {
    this.map = new Map();
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
    entry.msg = msg;
    entry.ttl = ttl;
    entry.modified = now();
    entry.eternal = eternal;

    this.map.set(id, entry);

    if (eternal)
      return this;

    return this;
  }

  insert(qs, zone, res, ad, eternal = false) {
    const msg = res.clone();
    msg.ad = ad;
    return this.add(qs, zone, msg, eternal);
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

    return entry.msg;
  }

  hit(qs, zone) {
    const msg = this.answer(qs, zone);

    if (!msg)
      return null;

    return msg.clone();
  }
}

/**
 * CacheEntry
 */

class CacheEntry {
  constructor() {
    this.msg = null;
    this.ttl = 0;
    this.modified = 0;
    this.eternal = false;
  }

  update(msg, ttl) {
    this.msg = msg;
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

function extractAnswer(msg, qs, ad) {
  const res = new Message();

  res.qr = true;
  res.opcode = msg.opcode;
  res.ra = true;
  res.ad = ad;
  res.code = msg.code;
  res.question = [qs];
  res.answer = msg.answer;
  res.authority = msg.authority;
  res.additional = msg.additional;

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
    return ['', null];

  if (filtered.length > 1) {
    if (!hasAll(filtered, types.CNAME) || qs.type === types.CNAME)
      return ['', null];
    const [sname, chased] = collapseChain(qs.name, filtered);
    return [sname, chased];
  }

  const alias = filtered[0];

  switch (alias.type) {
    case types.CNAME: {
      if (qs.type === types.CNAME || qs.name !== alias.name)
        return ['', null];
      return [alias.data.target, filtered];
    }
    case types.DNAME: {
      if (qs.type === types.DNAME)
        return ['', null];

      if (!qs.name.endsWith(alias.name))
        return ['', null];

      const sname = qs.name.slice(0, -alias.name.length) + alias.data.target;

      if (sname.length > MAX_DOMAIN_LENGTH)
        throw new Error('DNAME too long.');

      return [sname, filtered];
    }
  }

  return ['', null];
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
  return `${qs.name}${qs.type}${zone}`;
}

/*
 * Expose
 */

exports.DNSResolver = DNSResolver;
exports.StubResolver = StubResolver;
exports.RecursiveResolver = RecursiveResolver;
