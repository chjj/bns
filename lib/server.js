/*!
 * server.js - dns server for bns
 * Copyright (c) 2018, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bns
 */

'use strict';

const EventEmitter = require('events');
const {Server} = require('./net');
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
    const {port, address, tcp} = this.rinfo;
    const msg = this.toRaw(!tcp);
    return this.server.send(msg, 0, msg.length, port, address, tcp);
  }
}

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

    this.server.setRecvBufferSize(4096);
    this.server.setSendBufferSize(4096);
    this.server.maxConnections = 20;
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

    // if (req.aa || req.tc || req.ra || req.z || req.ad)
    //   throw new Error('Too many flags.');

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

  async handle(msg, rinfo) {
    const req = Message.fromRaw(msg);

    let res = null;

    try {
      res = await this.answer(req, rinfo);
    } catch (e) {
      res = new Message();
      res.respond(req);
      res.ra = this.ra;
      if (e.type === 'DNSError') {
        res.code = e.code;
      } else {
        res.code = codes.SERVERFAILURE;
        this.emit('error', e);
      }
    }

    if (res) {
      const {port, address, tcp} = rinfo;
      const msg = res.toRaw(!tcp);
      this.server.send(msg, 0, msg.length, port, address, tcp);
      this.emit('query', req, res, rinfo);
      return;
    }

    res = new Response(this.server, rinfo);
    res.ra = this.ra;
    res.respond(req);

    this.emit('query', req, res, rinfo);
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
    this.resolver.on('log', (...a) => this.emit('log', ...a));
    this.resolver.on('error', e => this.emit('error', e));
    this.ra = true;
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
    this.resolver.on('log', (...a) => this.emit('log', ...a));
    this.resolver.on('error', e => this.emit('error', e));
    this.ra = true;
  }
}

/*
 * Expose
 */

exports.DNSServer = DNSServer;
exports.StubServer = StubServer;
exports.RecursiveServer = RecursiveServer;
