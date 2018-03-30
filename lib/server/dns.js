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
const {Message, opcodes, codes} = require('../wire');
const {MAX_EDNS_SIZE} = constants;

/**
 * DNSServer
 * @extends EventEmitter
 */

class DNSServer extends EventEmitter {
  constructor(options) {
    super();

    this.server = new Server(options);
    this.resolver = null;

    this.inet6 = this.server.inet6;
    this.maxConnections = 20;
    this.ra = false;

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

    if (options.ra != null) {
      assert(typeof options.ra === 'boolean');
      this.ra = options.ra;
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
      throw new Error('Cannot respond to a response.');

    if (req.opcode !== opcodes.QUERY)
      throw new Error('Bad opcode.');

    if (req.code !== codes.NOERROR)
      throw new Error('Bad code.');

    if (req.question.length === 0)
      throw new Error('No question.');

    if (req.question.length > 1)
      throw new Error('Too many questions.');

    if (req.answer.length > 0)
      throw new Error('Too many answers.');

    if (req.authority.length > 0)
      throw new Error('Too many authorities.');

    const res = await this.resolve(req, rinfo);

    if (!res)
      return null;

    res.respond(req);
    res.ra = this.ra;

    return res;
  }

  send(res, rinfo) {
    const {port, address, tcp} = rinfo;
    const raw = res.compress(!tcp);
    const msg = this.sign(raw, address, port);

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

      this.send(res, rinfo);

      return;
    }

    try {
      res = await this.answer(req, rinfo);
    } catch (e) {
      this.emit('error', e);

      res = new Message();
      res.respond(req);
      res.ra = this.ra;
      res.code = codes.SERVFAIL;
    }

    if (res) {
      this.emit('query', req, res, rinfo);
      this.send(res, rinfo);
      return;
    }

    res = new Response(this, rinfo);
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
  constructor(server, rinfo) {
    super();
    this.server = server;
    this.rinfo = rinfo;
  }

  send() {
    this.server.send(this, this.rinfo);
  }
}

/*
 * Expose
 */

module.exports = DNSServer;
