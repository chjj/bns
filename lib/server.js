'use strict';

// https://github.com/miekg/dns/blob/master/msg.go
// https://github.com/miekg/dns/blob/master/msg_helpers.go
// https://github.com/miekg/dns/blob/master/types.go
// https://github.com/tigeli/bind-utils/blob/1acae3ea5e3048ebd121d4837ef989b57a05e54c/lib/dns/name.c

const assert = require('assert');
const dgram = require('dgram');
const EventEmitter = require('events');
const bio = require('bufio');
const wire = require('./wire');

const {
  Message,
  Question,
  Record,
  ARecord,
  AAAARecord,
  types,
  classes,
  codes,
  opcodes
} = wire;

function wrap(resolve, reject) {
  return function(err, result) {
    if (err) {
      reject(err);
      return;
    }
    resolve(result);
  };
}

class Response extends Message {
  constructor(server, rinfo) {
    super();
    this.server = server;
    this.rinfo = rinfo;
  }
  send() {
    const msg = this.toRaw();
    this.server.send(msg, 0, msg.length,
      this.rinfo.port, this.rinfo.address);
  }
}

class DNSServer extends EventEmitter {
  constructor(type = 'udp4') {
    super();
    assert(typeof type === 'string');
    this.server = dgram.createSocket(type);
    this._init();
  }

  _init() {
    this.server.on('error', (err) => {
      this.emit('error', err);
    });

    this.server.on('listening', () => {
      this.emit('listening');
    });

    this.server.on('message', (msg, rinfo) => {
      try {
        this._handleMessage(this.server, rinfo, msg);
      } catch (e) {
        this.emit('error', e);
      }
    });
  }

  address() {
    return this.server.address();
  }

  async open(port, host) {
    return new Promise((resolve, reject) => {
      this.server.bind(port, host, wrap(resolve, reject));
    });
  }

  async close() {
    return new Promise((resolve, reject) => {
      this.server.close(wrap(resolve, reject));
    });
  }

  _handleMessage(server, rinfo, msg) {
    const req = Message.fromRaw(msg);
    const res = new Response(server, rinfo);

    res.id = req.id;
    res.opcode = req.opcode;
    res.response = true;
    res.code = codes.NOERROR;
    res.question = req.question;

    this.emit('query', req, res);
  }
}

module.exports = DNSServer;
