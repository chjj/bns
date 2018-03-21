/*!
 * resolver.js - dns resolver for bns
 * Copyright (c) 2018, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bns
 */

'use strict';

const assert = require('assert');
const EventEmitter = require('events');
const {Client} = require('../net');
const encoding = require('../encoding');
const util = require('../util');
const wire = require('../wire');
const {equal, isSubdomain} = util;

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

    for (const item of pending.values()) {
      try {
        item.reject(new Error('Request cancelled.'));
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

    for (const item of this.pending.values()) {
      const {id, time, rinfo} = item;
      const {address} = rinfo;

      if (now > time + 2000) {
        this.log('Retrying (%s): %d...', address, id);
        this.retry(item, false);
      }
    }
  }

  verify(msg, host, port) {
    return true;
  }

  retry(item, forceTCP) {
    const {rinfo} = item;
    const {port, address} = rinfo;

    this.timer.unref();

    if (rinfo.tcp)
      this.socket.kill(port, address);

    if (item.retries >= this.maxRetries) {
      this.pending.delete(item.id);
      if (item.res)
        item.resolve(item.res);
      else
        item.reject(new Error('Request timed out.'));
      return;
    }

    if (forceTCP)
      rinfo.tcp = true;

    const {tcp} = rinfo;
    const msg = item.req.encode();

    // Retry over TCP or UDP.
    this.socket.send(msg, 0, msg.length, port, address, tcp);
    this.timer.ref();

    // Update time.
    item.time = Date.now();
    item.retries += 1;
  }

  handle(msg, rinfo) {
    const {port, address} = rinfo;

    this.timer.unref();

    // Close socket once we get an answer.
    if (rinfo.tcp)
      this.socket.drop(port, address);

    if (msg.length < 2) {
      this.log('Malformed message (%s).', address);
      return;
    }

    const id = msg.readUInt16BE(0, true);
    const item = this.pending.get(id);

    if (!item) {
      this.log('Unsolicited message (%s): %d.', address, id);
      return;
    }

    if (item.rinfo.address !== address
        || item.rinfo.port !== port) {
      this.log('Possible reflection attack (%s): %d.', address, id);
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
      item.reject(new Error('Invalid question.'));
      return;
    }

    if (res.tc) {
      if (rinfo.tcp) {
        this.pending.delete(id);
        item.reject(new Error('Truncated TCP msg.'));
        return;
      }

      // Retry over TCP if truncated.
      this.log('Retrying over TCP (%s): %d.', address, id);
      this.retry(item, true);

      return;
    }

    if (res.opcode !== opcodes.QUERY) {
      this.pending.delete(id);
      item.reject(new Error('Unexpected opcode.'));
      return;
    }

    if ((res.code === codes.FORMERR
        || res.code === codes.NOTIMP
        || res.code === codes.SERVFAIL)
        && (!res.isEDNS() && req.isEDNS())) {
      // They don't like edns.
      req = req.clone();
      req.unsetEDNS();
      item.req = req;
      item.res = res;
      this.log('Retrying without EDNS (%s): %d.', address, id);
      this.retry(item, false);
      return;
    }

    if (res.code === codes.FORMERR) {
      this.pending.delete(id);
      item.reject(new Error('Format error.'));
      return;
    }

    if (res.code === codes.SERVFAIL) {
      item.res = res;
      this.log('Retrying due to failure (%s): %d.', address, id);
      this.retry(item, false);
      return;
    }

    if (isLame(req, res)) {
      this.pending.delete(id);
      item.reject(new Error('Server is lame.'));
      return;
    }

    if (!this.verify(msg, address, port)) {
      this.pending.delete(id);
      item.reject(new Error('Could not verify response.'));
      return;
    }

    this.pending.delete(id);

    item.resolve(res);
  }

  async exchange(req, port, host) {
    assert(req instanceof Message);
    assert(typeof port === 'number');
    assert(typeof host === 'string');
    assert(util.isIP(host), 'Host must be an IP.');
    assert(req.question.length > 0);

    req.id = util.id();
    req.qr = false;

    const msg = req.encode();
    const tcp = msg.length >= 4096;

    this.socket.send(msg, 0, msg.length, port, host, tcp);
    this.timer.ref();

    return new Promise((resolve, reject) => {
      this.pending.set(req.id, {
        id: req.id,
        req,
        retries: 0,
        res: null,
        rinfo: {
          address: host,
          port,
          tcp
        },
        time: Date.now(),
        resolve,
        reject
      });
    });
  }

  async query(qs, port, host) {
    assert(qs instanceof Question);
    assert(typeof port === 'number');
    assert(typeof host === 'string');

    const req = new Message();
    req.opcode = opcodes.QUERY;
    req.rd = this.rd;
    req.question.push(qs);

    if (this.edns)
      req.setEDNS(4096, this.dnssec);

    return this.exchange(req, port, host);
  }

  async lookup(name, type, port, host) {
    const qs = new Question(name, type);
    return this.query(qs, port, host);
  }

  async reverse(addr, port, host) {
    const name = encoding.reverse(addr);
    return this.lookup(name, types.PTR, port, host);
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
