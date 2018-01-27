'use strict';

const EventEmitter = require('events');
const udp = require('budp');
const {Message, codes} = require('./wire');

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

class DNSServer extends EventEmitter {
  constructor(options) {
    super();
    this.server = udp.createSocket(options);
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

    this.server.on('message', (msg, rinfo) => {
      try {
        this.handle(rinfo, msg);
      } catch (e) {
        this.emit('error', e);
      }
    });
  }

  address() {
    return this.server.address();
  }

  async open(...args) {
    return this.server.bind(...args);
  }

  async close() {
    return this.server.close();
  }

  handle(rinfo, msg) {
    const req = Message.fromRaw(msg);
    const res = new Response(this.server, rinfo);

    res.id = req.id;
    res.opcode = req.opcode;
    res.response = true;
    res.code = codes.NOERROR;
    res.question = req.question;

    this.emit('query', req, res);
  }
}

module.exports = DNSServer;
