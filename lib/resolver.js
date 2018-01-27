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

class DNSResolver extends EventEmitter {
  constructor(type = 'udp4') {
    super();
    assert(typeof type === 'string');
    this.socket = dgram.createSocket(type);
    this.pending = new Map();
    this.id = 0;
    this.timer = null;
    this._init();
  }

  _init() {
    this.socket.on('error', (err) => {
      this.emit('error', err);
    });

    this.socket.on('listening', () => {
      this.emit('listening');
    });

    this.socket.on('message', (msg, rinfo) => {
      try {
        this._handleMessage(this.socket, rinfo, msg);
      } catch (e) {
        this.emit('error', e);
      }
    });
  }

  async open() {
    this.timer = setInterval(() => this._maybeTimeout(), 5000);
    return new Promise((resolve, reject) => {
      this.socket.bind(wrap(resolve, reject));
    });
  }

  async close() {
    clearInterval(this.timer);
    this.timer = null;
    this.pending.clear();
    this.id = 0;
    return new Promise((resolve, reject) => {
      this.socket.close(wrap(resolve, reject));
    });
  }

  _maybeTimeout() {
    const now = Math.floor(Date.now() / 1000);

    for (const [id, item] of this.pending) {
      if (now > item.time + 5 * 60) {
        this.pending.delete(id);
        item.reject(new Error('Request timed out.'));
      }
    }
  }

  _handleMessage(socket, rinfo, msg) {
    const res = Message.fromRaw(msg);
    const item = this.pending.get(res.id);

    if (!item)
      return;

    this.pending.delete(res.id);

    item.resolve(res);
  }

  async resolve(req, port, host) {
    req.id = this.id;
    req.response = false;

    this.id = (this.id + 1) & 0xffff;

    const msg = req.toRaw();

    this.socket.send(msg, 0, msg.length, port, host);

    return new Promise((resolve, reject) => {
      this.pending.set(req.id, {
        time: Math.floor(Date.now() / 1000),
        resolve,
        reject
      });
    });
  }
}

module.exports = DNSResolver;
