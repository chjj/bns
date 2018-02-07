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
const Heap = require('./heap');

const {
  Message,
  Question,
  Record,
  DNSKEYRecord,
  RRSIGRecord,
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

const ROOT_SIG = {
  typeCovered: types.DNSKEY,
  algorithm: 8,
  labels: 0,
  origTTL: 172800,
  expiration: 1519171200,
  inception: 1517356800,
  keyTag: 19036,
  signerName: '.',
  signature: ''
    + 'Zts1FYKbz3e1F5Wha6X1jXkqZusRI4TTgDgOxm0w7bWn+0jPNE/v5U7x'
    + 'DZlSwyL2X82sjv9X4+KSl/CLEokzTrI9eQNtDahVEYKSgF4gNeSAM7Sh'
    + 'MCoQ11yuPC/Id0kqgRFPth0zcb/l1bEIMmh76l5DnwoPduCTlXIajYeL'
    + '3boE/UCfRRQ0UVra9kAE0K5WUjpf6BjJsDTtkSx2jq+6gp7/Q/DTvU/f'
    + '1aBRdY/OtuImxkSHCgWn9h47IecB6urpUUxY+jDm0HRS9Ha841u4a1qS'
    + 'V7lx13MoWvvWQxNa8kNGBTpx5SPlSWB8W8hO/LAY7/8oQo7mTth59xc5'
    + 'GsPWnw=='
};

const MAX_DOMAIN_LENGTH = 256;
const MAX_REFERRALS = 20;
const MAX_RETRIES = 5;
const MAX_CACHE_SIZE = 20 << 20;

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

    const msg = item.req.toRaw();
    const {port, address} = item.rinfo;

    // Retry over TCP or UDP.
    this.socket.send(msg, 0, msg.length, port, address, tcp);

    // Update time.
    item.time = now();
    item.retries += 1;
  }

  handle(msg, rinfo) {
    // Close socket once we get an answer.
    if (rinfo.tcp) {
      const {port, address} = rinfo;
      this.socket.drop(port, address);
    }

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

    let {req} = item;
    let res = null;

    try {
      res = Message.fromRaw(msg);
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

    req.id = this.id;
    req.qr = false;

    this.id = (this.id + 1) & 0xffff;

    const msg = req.toRaw();
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
      host = randomItem(this.inet6 ? GOOGLE_IPV6 : GOOGLE_IPV4);
      host = IP.normalize(host);
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
    this.rootDS = [];
    this.nsec3 = false;
    this._init();
  }

  _init() {
    const msg = new Message();
    const qs = new Question('.', types.DNSKEY);

    msg.qr = true;
    msg.aa = true;
    msg.ad = true;
    msg.setEDNS0(4096, true);

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
      this.rootDS.push(ds);
    }

    const data = ROOT_SIG;
    const rd = new RRSIGRecord();

    rd.typeCovered = data.typeCovered;
    rd.algorithm = data.algorithm;
    rd.labels = data.labels;
    rd.origTTL = data.origTTL;
    rd.expiration = data.expiration;
    rd.inception = data.inception;
    rd.keyTag = data.keyTag;
    rd.signerName = data.signerName;
    rd.signature = Buffer.from(data.signature, 'base64');

    const rr = new Record();
    rr.name = '.';
    rr.type = types.RRSIG;
    rr.ttl = 172800;
    rr.data = rd;
    msg.answer.push(rr);

    this.cache.insert(qs, '.', msg, true, true);
  }

  randomAuthority() {
    const [ch, ipv4, ipv6] = randomItem(ROOT_SERVERS);
    const name = `${ch}.root-servers.net.`;
    const ip = this.inet6 ? ipv6 : ipv4;
    return new Authority(name, IP.normalize(ip));
  }

  async hook(qs, auth) {
    return [null, null];
  }

  async ask(qs, auth) {
    const [msg, rewrite] = await this.hook(qs, auth);

    if (msg) {
      if (rewrite)
        qs.name = rewrite;
      return [msg, true, rewrite];
    }

    const {zone, port, host} = auth;
    const cache = this.cache.hit(qs, zone);

    if (cache) {
      this.log('Cache hit for %s/%d.', qs.name, qs.type);
      return [cache, true, null];
    }

    const res = await this.query(qs, port, host, false);

    return [res, false, null];
  }

  async findNS(rc, name, type) {
    const qs = new Question(name, type);
    const ns = this.randomAuthority();
    const child = await this._resolve(qs, ns, rc.hops);
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

  async lookupDNSKEY(qs, auth, ds) {
    const [res, hit] = await this.ask(qs, auth);
    const keyMap = new Map();

    if (res.answer.length === 0
        || res.code !== codes.NOERROR) {
      return [res, hit, keyMap];
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
      ds = this.rootDS;
    }

    assert(ds.length > 0);

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

    return [res, hit, keyMap];
  }

  async checkSignatures(msg, auth, ds) {
    const qs = new Question(auth.zone, types.DNSKEY);
    const [res, hit, keyMap] = await this.lookupDNSKEY(qs, auth, ds);

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

      // if (rc.ds.length === 0) {
      //   const qs = new Question(auth.zone, types.DS);
      //   const [msg, hit] = await this.ask(qs, rc.auth);
      //
      //   if (!hit && msg.code === codes.NOERROR)
      //     this.cache.insert(qs, rc.auth.zone, msg, false);
      //
      //   rc.ds = extractSet(msg.authority, auth.zone, types.DS);
      //
      //   if (rc.ds.length === 0) {
      //     rc.chain = false;
      //     this.log('Trust chain broken due to zone change.');
      //   }
      // }
    }

    rc.switchZone(auth);
    rc.hop();

    return true;
  }

  async lookupNext(rc) {
    const [res, hit, rewrite] = await this.ask(rc.qs, rc.auth);
    rc.res = res;
    rc.hit = hit;
    if (rewrite)
      rc.rewritten = true;
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

    if (this.nsec3 && rc.chain && rc.res.code === codes.NAMEERROR) {
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

  async _resolve(qs, ns, hops) {
    if (ns == null)
      ns = this.randomAuthority();

    if (hops == null)
      hops = 0;

    assert(qs instanceof Question);
    assert(ns && typeof ns === 'object');
    assert(typeof hops === 'number');

    if (qs.class !== classes.INET
        && qs.class !== classes.ANY) {
      throw new Error('Unknown class.');
    }

    const rc = new ResolveContext(qs, ns, hops);

    return this.iterate(rc);
  }

  async resolve(qs, ns) {
    const rc = await this._resolve(qs, ns, 0);

    this.log('Finishing resolving %s/%d (hops=%d).', qs.name, qs.type, rc.hops);

    return rc.toAnswer();
  }

  async lookup(name, type, ns) {
    const qs = new Question(name, type);
    return this.resolve(qs, ns);
  }

  async reverse(addr, ns) {
    const name = encoding.reverse(addr);
    return this.lookup(name, types.PTR, ns);
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
    this.rewritten = false;
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
    return `${qs.name}${qs.type}${zone}`;
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

      const raw = msg.toRaw();

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

    const raw = msg.toRaw();
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

    return Message.fromRaw(entry.msg);
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

exports.DNSResolver = DNSResolver;
exports.StubResolver = StubResolver;
exports.RecursiveResolver = RecursiveResolver;
