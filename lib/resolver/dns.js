/*!
 * resolver.js - dns resolver for bns
 * Copyright (c) 2018, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bns
 */

'use strict';

const assert = require('assert');
const EventEmitter = require('events');
const IP = require('binet');
const {Client} = require('../net');
const encoding = require('../encoding');
const util = require('../util');
const wire = require('../wire');
const {equal, isSubdomain, sortRandom} = util;

const {
  Message,
  Question,
  opcodes,
  types,
  codes
} = wire;

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
    this.maxRetries = 5;
    this.rd = false;
    this.edns = false;
    this.dnssec = false;

    this.init();
  }

  init() {
    this.on('error', () => {});

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

  parseOptions(options) {
    if (options == null)
      return this;

    assert(options && typeof options === 'object');

    if (options.maxRetries != null) {
      assert((options.maxRetries >>> 0) === options.maxRetries);
      this.maxRetries = options.maxRetries;
    }

    if (options.rd != null) {
      assert(typeof options.rd === 'boolean');
      this.rd = options.rd;
    }

    if (options.edns != null) {
      assert(typeof options.edns === 'boolean');
      this.edns = options.edns;
    }

    if (options.dnssec != null) {
      assert(typeof options.dnssec === 'boolean');
      this.dnssec = options.dnssec;
    }

    return this;
  }

  initOptions(options) {
    return this.parseOptions(options);
  }

  log(...args) {
    this.emit('log', ...args);
  }

  async open(...args) {
    await this.socket.bind(...args);

    this.socket.setRecvBufferSize(4096);
    this.socket.setSendBufferSize(4096);

    this.timer = setInterval(() => this.timeout(), 1000);
    this.timer.unref();

    return this;
  }

  async close() {
    await this.socket.close();

    if (this.timer != null) {
      clearInterval(this.timer);
      this.timer = null;
    }

    this.cancel();

    return this;
  }

  cancel() {
    const pending = this.pending;

    this.pending = new Map();

    for (const query of pending.values()) {
      try {
        query.reject(new Error('Request cancelled.'));
      } catch (e) {
        this.emit('error', e);
      }
    }

    return this;
  }

  async bind(...args) {
    return this.open(...args);
  }

  timeout() {
    const now = Date.now();

    for (const query of this.pending.values()) {
      if (now > query.time + 2000)
        this.retry(query, false, true);
    }
  }

  verify(msg, host, port) {
    return true;
  }

  retry(query, forceTCP, rotate) {
    let server = query.server;

    this.timer.unref();

    if (query.server.tcp) {
      const {port, host} = server;
      this.socket.kill(port, host);
    }

    if (query.retries >= this.maxRetries) {
      this.pending.delete(query.id);
      if (query.res)
        query.resolve(query.res);
      else
        query.reject(new Error('Request timed out.'));
      return;
    }

    if (forceTCP) {
      server.tcp = true;
    } else if (rotate) {
      server = query.nextServer(server.tcp);
      this.log('Switched servers to: %s (%d).', server.host, query.id);
    }

    const {port, host, tcp} = server;
    const msg = query.req.encode();

    // Retry over TCP or UDP.
    this.socket.send(msg, 0, msg.length, port, host, tcp);
    this.timer.ref();

    this.log('Retrying (%s): %d (tcp=%s)...', host, query.id, tcp);

    // Update time.
    query.time = Date.now();
    query.retries += 1;
  }

  handle(msg, rinfo) {
    this.timer.unref();

    // Close socket once we get an answer.
    if (rinfo.tcp) {
      const {port, address} = rinfo;
      this.socket.drop(port, address);
    }

    if (msg.length < 2) {
      this.log('Malformed message (%s).', rinfo.address);
      return;
    }

    const id = msg.readUInt16BE(0, true);
    const query = this.pending.get(id);

    if (!query) {
      this.log('Unsolicited message (%s): %d.', rinfo.address, id);
      return;
    }

    const {host, port} = query.server;

    if (rinfo.address !== host || port !== rinfo.port) {
      this.log(
        'Possible reflection attack (%s != %s): %d.',
        rinfo.address, host, id);
      return;
    }

    let {req} = query;
    let res = null;

    try {
      res = Message.decode(msg);
    } catch (e) {
      this.pending.delete(id);
      query.reject(e);
      return;
    }

    if (!res.qr) {
      this.pending.delete(id);
      query.reject(new Error('Not a response.'));
      return;
    }

    if (!sameQuestion(req, res)) {
      this.pending.delete(id);
      query.reject(new Error('Invalid question.'));
      return;
    }

    if (res.tc) {
      if (rinfo.tcp) {
        this.pending.delete(id);
        query.reject(new Error('Truncated TCP msg.'));
        return;
      }

      // Retry over TCP if truncated.
      this.log('Retrying over TCP (%s): %d.', host, id);
      this.retry(query, true, false);

      return;
    }

    if (res.opcode !== opcodes.QUERY) {
      this.pending.delete(id);
      query.reject(new Error('Unexpected opcode.'));
      return;
    }

    if ((res.code === codes.FORMERR
        || res.code === codes.NOTIMP
        || res.code === codes.SERVFAIL)
        && (!res.isEDNS() && req.isEDNS())) {
      // They don't like edns.
      req = req.clone();
      req.unsetEDNS();

      query.req = req;
      query.res = res;

      this.log('Retrying without EDNS (%s): %d.', host, id);
      this.retry(query, false, false);
      return;
    }

    if (res.code === codes.FORMERR) {
      this.pending.delete(id);
      query.reject(new Error('Format error.'));
      return;
    }

    if (res.code === codes.SERVFAIL) {
      query.res = res;
      this.log('Retrying due to failure (%s): %d.', host, id);
      this.retry(query, false, true);
      return;
    }

    if (isLame(req, res)) {
      this.pending.delete(id);
      query.reject(new Error('Server is lame.'));
      return;
    }

    if (!this.verify(msg, host, port)) {
      this.pending.delete(id);
      query.reject(new Error('Could not verify response.'));
      return;
    }

    this.pending.delete(id);

    query.resolve(res);
  }

  async exchange(req, servers) {
    assert(req instanceof Message);
    assert(Array.isArray(servers));
    assert(req.question.length > 0);

    const [qs] = req.question;

    if (!util.isName(qs.name))
      throw new Error('Invalid qname.');

    if (servers.length === 0)
      throw new Error('No servers available.');

    req.id = util.id();
    req.qr = false;

    const msg = req.encode();
    const tcp = msg.length >= 4096;
    const query = new Query(req, servers, tcp);
    const {port, host} = query.server;

    this.log('Querying server: %s (%d)', host, req.id);

    this.socket.send(msg, 0, msg.length, port, host, tcp);
    this.timer.ref();
    this.pending.set(query.id, query);

    return new Promise((resolve, reject) => {
      query.resolve = resolve;
      query.reject = reject;
    });
  }

  async query(qs, servers) {
    assert(qs instanceof Question);
    assert(Array.isArray(servers));

    const req = new Message();
    req.opcode = opcodes.QUERY;
    req.rd = this.rd;
    req.question.push(qs);

    if (this.edns)
      req.setEDNS(4096, this.dnssec);

    return this.exchange(req, servers);
  }

  async lookup(name, type, servers) {
    const qs = new Question(name, type);
    return this.query(qs, servers);
  }

  async reverse(addr, servers) {
    const name = encoding.reverse(addr);
    return this.lookup(name, types.PTR, servers);
  }
}

/**
 * Query
 */

class Query {
  constructor(req, servers, tcp) {
    assert(req instanceof Message);
    assert(Array.isArray(servers));
    assert(servers.length > 0);
    assert(typeof tcp === 'boolean');

    this.id = req.id;
    this.req = req;
    this.index = 0;
    this.servers = servers;
    this.resolve = null;
    this.reject = null;
    this.retries = 0;
    this.res = null;
    this.server = null;
    this.time = 0;
    this.init(tcp);
  }

  init(tcp) {
    this.servers = sortRandom(this.servers);
    this.server = this.nextServer(tcp);
    this.time = Date.now();
  }

  getServer(index, tcp) {
    assert((index >>> 0) < this.servers.length);
    assert(typeof tcp === 'boolean');

    const server = this.servers[index];

    let addr;

    if (typeof addr === 'string') {
      addr = IP.fromHost(server, 53);
    } else {
      if (!server || typeof server !== 'object')
        throw new Error('Bad address passed to query.');
      addr = server;
    }

    const host = addr.address || addr.host;
    const port = addr.port || 53;

    if (typeof host !== 'string')
      throw new Error('Bad address passed to query.');

    if (!util.isIP(host))
      throw new Error('Bad address passed to query.');

    if ((port & 0xffff) !== port)
      throw new Error('Bad address passed to query.');

    return { host: IP.normalize(host), port, tcp };
  }

  nextServer(tcp) {
    this.index += 1;

    if (this.index === this.servers.length)
      this.index = 0;

    this.server = this.getServer(this.index, tcp);

    return this.server;
  }
}

/*
 * Helpers
 */

function sameQuestion(req, res) {
  switch (res.code) {
    case codes.NOTIMP:
    case codes.FORMERR:
    case codes.NXRRSET:
      if (res.question.length === 0)
        break;
    case codes.BADCOOKIE:
    case codes.NOERROR:
    case codes.NXDOMAIN:
    case codes.YXDOMAIN:
    case codes.REFUSED:
    case codes.SERVFAIL:
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

    if (equal(rr.name, name))
      continue;

    if (isSubdomain(rr.name, name))
      continue;

    return true;
  }

  return false;
}

/*
 * Expose
 */

module.exports = DNSResolver;
