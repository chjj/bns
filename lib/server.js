/*!
 * server.js - dns server for bns
 * Copyright (c) 2018, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bns
 */

'use strict';

const EventEmitter = require('events');
const udp = require('budp');
const {Message, opcodes, codes} = require('./wire');
const {StubResolver, RecursiveResolver} = require('./resolver');

/**
 * Response
 * @extends EventEmitter
 */

class Response extends Message {
  constructor(server, rinfo) {
    super();
    this.server = server;
    this.rinfo = rinfo;
  }
  async send() {
    const msg = this.toRaw();
    const {port, address} = this.rinfo;
    return this.server.send(msg, 0, msg.length, port, address);
  }
}

/**
 * DNSServer
 * @extends EventEmitter
 */

class DNSServer extends EventEmitter {
  constructor(options) {
    super();
    this.server = udp.createSocket(options);
    this.resolver = null;
    this.init();
  }

  init() {
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

  address() {
    return this.server.address();
  }

  async open(...args) {
    if (this.resolver)
      await this.resolver.open();
    return this.server.bind(...args);
  }

  async close() {
    await this.server.close();
    if (this.resolver)
      return this.resolver.close();
    return undefined;
  }

  async bind(...args) {
    if (this.resolver)
      await this.resolver.open();
    return this.open(...args);
  }

  async answer(req) {
    if (!this.resolver)
      return null;

    if (req.response)
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

    const [qs] = req.question;
    const res = await this.resolver.resolve(qs);
    res.id = req.id;
    res.recursionDesired = req.recursionDesired;
    res.checkingDisabled = req.checkingDisabled;

    return res;
  }

  async handle(msg, rinfo) {
    const req = Message.fromRaw(msg);

    let res = null;

    try {
      res = await this.answer(req);
    } catch (e) {
      res = new Message();
      res.id = req.id;
      res.opcode = req.opcode;
      res.response = true;
      if (e.type === 'DNSError') {
        res.code = e.code;
      } else {
        res.code = codes.SERVERFAILURE;
        this.emit('error', e);
      }
    }

    if (res) {
      const msg = res.toRaw();
      const {port, address} = rinfo;
      this.server.send(msg, 0, msg.length, port, address);
      this.emit('query', req, res);
      return;
    }

    res = new Response(this.server, rinfo);
    res.id = req.id;
    res.opcode = req.opcode;
    res.response = true;
    res.recursionDesired = req.recursionDesired;
    res.question = req.question;

    this.emit('query', req, res);
  }
}

/**
 * StubServer
 * @extends EventEmitter
 */

class StubServer extends DNSServer {
  constructor(options) {
    super(options);
    this.resolver = new StubResolver(options);
  }
}

/**
 * RecursiveServer
 * @extends EventEmitter
 */

class RecursiveServer extends DNSServer {
  constructor(options) {
    super(options);
    this.resolver = new RecursiveResolver(options);
  }
}

/*
 * Expose
 */

exports.DNSServer = DNSServer;
exports.StubServer = StubServer;
exports.RecursiveServer = RecursiveServer;
