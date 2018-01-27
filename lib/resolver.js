'use strict';

const udp = require('budp');
const EventEmitter = require('events');
const {Message} = require('./wire');

class DNSResolver extends EventEmitter {
  constructor(options) {
    super();
    this.socket = udp.createSocket(options);
    this.pending = new Map();
    this.id = 0;
    this.timer = null;
    this.init();
  }

  init() {
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
        this.handle(rinfo, msg);
      } catch (e) {
        this.emit('error', e);
      }
    });
  }

  async open(...args) {
    this.timer = setInterval(() => this.timeout(), 5000);
    return this.socket.bind(...args);
  }

  async close() {
    clearInterval(this.timer);
    this.timer = null;
    this.pending.clear();
    this.id = 0;
    return this.socket.close();
  }

  timeout() {
    const now = Math.floor(Date.now() / 1000);

    for (const [id, item] of this.pending) {
      if (now > item.time + 5 * 60) {
        this.pending.delete(id);
        item.reject(new Error('Request timed out.'));
      }
    }
  }

  handle(rinfo, msg) {
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
