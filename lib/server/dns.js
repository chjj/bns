/*!
 * dns.js - dns server for bns
 * Copyright (c) 2018, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bns
 */

'use strict';

const assert = require('assert');
const EventEmitter = require('events');
const constants = require('../constants');
const {Server} = require('../net');
const {Message, codes} = require('../wire');
const {MAX_EDNS_SIZE, MAX_MSG_SIZE} = constants;

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
    this.maxConnections = 20;

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

    return this;
  }

  initOptions(options) {
    return this.parseOptions(options);
  }

  log(...args) {
    this.emit('log', ...args);
  }

  address() {
    return this.server.address();
  }

  async open(...args) {
    if (this.resolver)
      await this.resolver.open();

    await this.server.bind(...args);

    this.server.setRecvBufferSize(MAX_EDNS_SIZE);
    this.server.setSendBufferSize(MAX_EDNS_SIZE);
    this.server.maxConnections = this.maxConnections;
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

  async resolve(req, rinfo) {
    if (!this.resolver)
      return null;

    const [qs] = req.question;

    return this.resolver.resolve(qs);
  }

  async answer(req, rinfo) {
    if (req.qr)
      throw new Error('EFORMERR');

    if (req.code !== codes.NOERROR)
      throw new Error('EFORMERR');

    if (req.question.length === 0)
      throw new Error('EFORMERR');

    if (req.question.length > 1)
      throw new Error('EFORMERR');

    if (req.answer.length > 0)
      throw new Error('EFORMERR');

    if (req.authority.length > 0)
      throw new Error('EFORMERR');

    const res = await this.resolve(req, rinfo);

    if (!res)
      return null;

    res.respond(req);
    res.ra = this.ra;

    return res;
  }

  send(req, res, rinfo) {
    const {port, address, tcp} = rinfo;

    let msg;
    if (tcp) {
      msg = res.compress();
      msg = this.sign(msg, address, port);

      if (msg.length > MAX_MSG_SIZE)
        throw new Error('Message exceeds size limits.');
    } else {
      const max = req.maxSize() - this.signSize();

      if (max < 0)
        throw new Error('Invalid sign size (>500).');

      msg = res.compress(true, max);
      msg = this.sign(msg, address, port);

      if (msg.length > max)
        throw new Error('Invalid sign size (too low).');
    }

    this.server.send(msg, 0, msg.length, port, address, tcp);
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
      res.id = msg.readUInt16BE(0, true);
      res.ra = this.ra;
      res.qr = true;
      res.code = codes.FORMERR;

      this.send(req, res, rinfo);

      return;
    }

    try {
      res = await this.answer(req, rinfo);
    } catch (e) {
      this.emit('error', e);

      res = new Message();
      res.respond(req);
      res.ra = this.ra;

      if (e.message === 'EFORMERR')
        res.code = codes.FORMERR;
      else
        res.code = codes.SERVFAIL;
    }

    if (res) {
      this.emit('query', req, res, rinfo);
      this.send(req, res, rinfo);
      return;
    }

    res = new Response(this, req, rinfo);
    res.respond(req);
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
    this.server = server;
    this.req = req;
    this.rinfo = rinfo;
  }

  send() {
    this.server.send(this.req, this, this.rinfo);
  }
}

/*
 * Expose
 */

module.exports = DNSServer;
