/*!
 * dns.js - dns server for bns
 * Copyright (c) 2018, Christopher Jeffrey (MIT License).
 * https://github.com/chjj/bns
 */

'use strict';

const assert = require('bsert');
const EventEmitter = require('events');
const bio = require('bufio');
const constants = require('../constants');
const dnssec = require('../dnssec');
const DNSError = require('../error');
const {Server} = require('../internal/net');
const wire = require('../wire');

const {
  codes,
  options,
  types,
  MAX_EDNS_SIZE,
  MAX_UDP_SIZE,
  MAX_MSG_SIZE
} = constants;

const {
  Message
} = wire;

/**
 * DNSServer
 * @extends EventEmitter
 */

class DNSServer extends EventEmitter {
  constructor(options) {
    super();

    this.server = new Server(options);
    this.resolver = null;
    this.ra = false;

    this.inet6 = this.server.inet6;
    this.tcp = this.server.tcp;
    this.maxConnections = 20;
    this.edns = false;
    this.ednsSize = MAX_EDNS_SIZE;
    this.dnssec = false;
    this.noAny = false;

    this.init();
  }

  init() {
    this.on('error', () => {});

    this.server.on('close', () => {
      this.emit('close');
    });

    this.server.on('error', (err) => {
      this.emit('error', err);
    });

    this.server.on('listening', () => {
      this.emit('listening');
    });

    this.server.on('message', async (msg, rinfo) => {
      try {
        await this.handle(msg, rinfo);
      } catch (e) {
        this.emit('error', e);
      }
    });
  }

  parseOptions(options) {
    if (options == null)
      return this;

    assert(options && typeof options === 'object');

    if (options.maxConnections != null) {
      assert((options.maxConnections >>> 0) === options.maxConnections);
      this.maxConnections = options.maxConnections;
    }

    if (options.edns != null) {
      assert(typeof options.edns === 'boolean');
      this.edns = options.edns;
    }

    if (options.ednsSize != null) {
      assert((options.ednsSize >>> 0) === options.ednsSize);
      assert(options.ednsSize >= MAX_UDP_SIZE);
      assert(options.ednsSize <= MAX_EDNS_SIZE);
      this.ednsSize = options.ednsSize;
    }

    if (options.dnssec != null) {
      assert(typeof options.dnssec === 'boolean');
      this.dnssec = options.dnssec;
      if (this.dnssec)
        this.edns = true;
    }

    if (options.noAny != null) {
      assert(typeof options.noAny === 'boolean');
      this.noAny = options.noAny;
    }

    return this;
  }

  initOptions(options) {
    return this.parseOptions(options);
  }

  log(...args) {
    this.emit('log', ...args);
    return this;
  }

  address() {
    return this.server.address();
  }

  async open(...args) {
    if (this.resolver)
      await this.resolver.open();

    await this.server.bind(...args);

    this.server.maxConnections = this.maxConnections;

    if (this.edns) {
      this.server.setRecvBufferSize(this.ednsSize);
      this.server.setSendBufferSize(this.ednsSize);
    } else {
      this.server.setRecvBufferSize(MAX_UDP_SIZE);
      this.server.setSendBufferSize(MAX_UDP_SIZE);
    }

    return this;
  }

  async close() {
    await this.server.close();

    if (!this.resolver)
      return undefined;

    return this.resolver.close();
  }

  async bind(...args) {
    return this.open(...args);
  }

  signSize() {
    return 0;
  }

  sign(msg, host, port) {
    return msg;
  }

  finalize(req, res) {
    assert(req instanceof Message);
    assert(res instanceof Message);

    const ds = this.dnssec && req.isDNSSEC();

    res.setReply(req);
    res.ra = this.ra;

    if (this.edns && req.isEDNS()) {
      res.setEDNS(this.ednsSize, ds);

      if (this.ra) {
        // Echo cookies if we're recursive.
        for (const opt of req.edns.options) {
          if (opt.code === options.COOKIE) {
            res.edns.options.push(opt);
            break;
          }
        }
      }
    } else {
      res.unsetEDNS();
    }

    if (this.ra) {
      if (res.answer.length > 0) {
        res.authority = [];
        res.additional = [];
      }

      if (!ds && !req.ad)
        res.ad = false;
    }

    if (!ds && req.question.length > 0) {
      const [qs] = req.question;

      // If we're recursive, and the
      // query was ANY, do not remove.
      if (!this.ra || qs.type !== types.ANY)
        dnssec.filterMessage(res, qs.type);
    }

    res.refresh();

    return this;
  }

  async resolve(req, rinfo) {
    if (!this.resolver)
      return null;

    const [qs] = req.question;

    return this.resolver.resolve(qs);
  }

  async answer(req, rinfo) {
    if (req.qr)
      throw new DNSError('unexpected qr bit', codes.FORMERR);

    if (req.code !== codes.NOERROR)
      throw new DNSError('unexpected rcode', codes.FORMERR);

    if (req.question.length !== 1)
      throw new DNSError('invalid question', codes.FORMERR);

    if (req.answer.length > 0)
      throw new DNSError('unexpected answer', codes.FORMERR);

    if (req.authority.length > 0)
      throw new DNSError('unexpected authority', codes.FORMERR);

    const [qs] = req.question;

    if (this.noAny && qs.type === types.ANY)
      throw new DNSError('ANY not accepted', codes.NOTIMP);

    const res = await this.resolve(req, rinfo);

    if (!res)
      return null;

    this.finalize(req, res);

    return res;
  }

  send(req, res, rinfo) {
    const {port, address, tcp} = rinfo;

    let msg;

    if (this.tcp && tcp) {
      msg = res.compress();
      msg = this.sign(msg, address, port);

      if (msg.length > MAX_MSG_SIZE)
        throw new Error('Message exceeds size limits.');
    } else {
      const maxSize = this.edns && req
        ? req.maxSize(this.ednsSize)
        : MAX_UDP_SIZE;

      const max = maxSize - this.signSize();

      if ((max >>> 0) !== max || max < 12)
        throw new Error('Invalid sign size.');

      msg = res.compress(max);
      msg = this.sign(msg, address, port);

      if (msg.length > maxSize)
        throw new Error('Invalid sign size.');
    }

    this.server.send(msg, 0, msg.length, port, address, tcp);

    return this;
  }

  async handle(msg, rinfo) {
    let req = null;
    let res = null;

    try {
      req = Message.decode(msg);
    } catch (e) {
      this.emit('error', e);

      if (msg.length < 2)
        return;

      res = new Message();
      res.id = bio.readU16BE(msg, 0);
      res.ra = this.ra;
      res.qr = true;
      res.code = codes.FORMERR;

      this.send(null, res, rinfo);

      return;
    }

    try {
      res = await this.answer(req, rinfo);
    } catch (e) {
      this.emit('error', e);

      res = new Message();
      res.code = codes.SERVFAIL;

      if (e.type === 'DNSError')
        res.code = e.errno;

      this.finalize(req, res);
    }

    if (res) {
      this.emit('query', req, res, rinfo);
      this.send(req, res, rinfo);
      return;
    }

    res = new Response(this, req, rinfo);
    res.setReply(req);
    res.ra = this.ra;

    this.emit('query', req, res, rinfo);
  }
}

/**
 * Response
 * @extends Message
 */

class Response extends Message {
  constructor(server, req, rinfo) {
    super();
    this._server = server;
    this._req = req;
    this._rinfo = rinfo;
    this._sent = false;
  }

  send() {
    if (this._sent)
      throw new Error('Response already sent.');

    this._sent = true;

    this._server.finalize(this._req, this);
    this._server.send(this._req, this, this._rinfo);
  }
}

/*
 * Expose
 */

module.exports = DNSServer;
