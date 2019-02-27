/*!
 * net.js - dns server for bns
 * Copyright (c) 2018, Christopher Jeffrey (MIT License).
 * https://github.com/chjj/bns
 */

'use strict';

const assert = require('bsert');
const EventEmitter = require('events');
const IP = require('binet');
const tcp = require('btcp');
const udp = require('budp');
const bio = require('bufio');
const util = require('../util');
const hasIPv6 = IP.getPublic('ipv6').length > 0;

/**
 * Base
 * @extends EventEmitter
 */

class Base extends EventEmitter {
  /**
   * Create a base socket.
   * @constructor
   * @param {Function?} handler
   */

  constructor(options) {
    super();

    const opt = normalize(options);

    this.inet6 = opt.type === 'udp6';
    this.tcp = true;
    this.socket = udp.createSocket(opt);
    this.sockets = new Map();

    if (options && typeof options === 'object') {
      if (options.tcp != null) {
        assert(typeof options.tcp === 'boolean');
        this.tcp = options.tcp;
      }

      if (options.forceTCP != null) {
        assert(typeof options.forceTCP === 'boolean');
        if (options.forceTCP)
          this.tcp = true;
      }
    }

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
      const {address, port} = rinfo;
      const ip = IP.toBuffer(address);
      const v4 = IP.isIPv4(ip);
      this.emit('message', msg, {
        tcp: false,
        family: v4 ? 'IPv4' : 'IPv6',
        address: IP.toString(ip),
        port
      });
    });
  }

  addMembership(addr, iface) {
    this.socket.addMembership(addr, iface);
    return this;
  }

  address() {
    const {address, port} = this.socket.address();
    const host = this.inet6 ? ensure6(address) : ensure4(address);
    const ip = IP.toBuffer(host);
    const v4 = IP.isIPv4(ip);
    return {
      family: v4 ? 'IPv4' : 'IPv6',
      address: IP.toString(ip),
      port
    };
  }

  async bind(...args) {
    if (args.length > 1) {
      const [, host] = args;
      if (typeof host === 'string') {
        assert(util.isIP(host), 'Must bind to an IP address.');
        args[1] = this.inet6 ? ensure6(host) : ensure4(host);
      }
    }
    return this.socket.bind(...args);
  }

  async close() {
    for (const socket of this.sockets.values())
      socket.destroy();
    return this.socket.close();
  }

  dropMembership(addr, iface) {
    this.socket.dropMembership(addr, iface);
    return this;
  }

  getRecvBufferSize() {
    return this.socket.getRecvBufferSize();
  }

  getSendBufferSize() {
    return this.socket.getSendBufferSize();
  }

  ref() {
    this.socket.ref();
    return this;
  }

  async write(msg, port, host) {
    throw new Error('Abstract.');
  }

  async send(msg, pos, len, port, host, tcp) {
    if (this.tcp && tcp) {
      if (pos !== 0 && len !== msg.length)
        msg = msg.slice(pos, pos + len);
      return this.write(msg, port, host);
    }

    host = this.inet6 ? ensure6(host) : ensure4(host);

    return this.socket.send(msg, pos, len, port, host);
  }

  setBroadcast(flag) {
    this.socket.setBroadcast(flag);
    return this;
  }

  setMulticastInterface(iface) {
    this.socket.setMulticastInterface(iface);
    return this;
  }

  setMulticastLoopback(flag) {
    this.socket.setMulticastLoopback(flag);
    return this;
  }

  setMulticastTTL(ttl) {
    this.socket.setMulticastTTL(ttl);
    return this;
  }

  setRecvBufferSize(size) {
    this.socket.setRecvBufferSize(size);
    return this;
  }

  setSendBufferSize(size) {
    this.socket.setSendBufferSize(size);
    return this;
  }

  setTTL(ttl) {
    this.socket.setTTL(ttl);
    return this;
  }

  unref() {
    this.socket.unref();
    return this;
  }
}

/**
 * Client
 * @extends EventEmitter
 */

class Client extends Base {
  /**
   * Create a UDP socket.
   * @constructor
   * @param {Function?} handler
   */

  constructor(options) {
    super(options);
    this.socket.unref();
  }

  async write(msg, port, host) {
    const key = IP.toHost(host, port);
    const cache = this.sockets.get(key);

    if (cache) {
      cache.write(msg);
      return;
    }

    let socket = null;

    try {
      socket = await TCPSocket.connect(this, port, host);
    } catch (e) {
      return;
    }

    if (this.sockets.has(key)) {
      socket.destroy();
      socket = this.sockets.get(key);
    } else {
      socket.parent = this;
      this.sockets.set(key, socket);
    }

    socket.write(msg);
  }

  drop(port, host) {
    const key = IP.toHost(host, port);
    const socket = this.sockets.get(key);
    if (socket && socket.pending === 0)
      socket.destroy();
  }

  kill(port, host) {
    const key = IP.toHost(host, port);
    const socket = this.sockets.get(key);
    if (socket)
      socket.destroy();
  }
}

/**
 * Server
 * @extends EventEmitter
 */

class Server extends Base {
  /**
   * Create a UDP socket.
   * @constructor
   * @param {Function?} handler
   */

  constructor(options) {
    super(options);

    this.server = tcp.createServer();

    this.server.on('error', (err) => {
      this.emit('error', err);
    });

    this.server.on('connection', (conn) => {
      try {
        this._handleSocket(conn);
      } catch (e) {
        this.emit('error', e);
      }
    });
  }

  _handleSocket(conn) {
    if (!conn.remoteAddress) {
      conn.destroy();
      return;
    }

    const socket = TCPSocket.accept(this, conn);
    const key = IP.toHost(socket.host, socket.port);

    this.sockets.set(key, socket);
  }

  async bind(...args) {
    if (this.tcp)
      await this.server.listen(...args);
    return super.bind(...args);
  }

  async close() {
    if (this.tcp)
      await this.server.close();
    return super.close();
  }

  async write(msg, port, host) {
    const key = IP.toHost(host, port);
    const socket = this.sockets.get(key);

    if (socket)
      socket.write(msg);
  }

  get maxConnections() {
    return this.server.maxConnections;
  }

  set maxConnections(max) {
    this.server.maxConnections = max;
  }
}

/**
 * TCPSocket
 * @extends EventEmitter
 */

class TCPSocket extends EventEmitter {
  constructor(parent) {
    super();

    assert(parent);

    this.parent = parent;
    this.socket = new tcp.Socket();
    this.ctimer = null;
    this.btimer = null;
    this.connected = false;
    this.destroyed = false;
    this.parser = new Parser();
    this.buffered = 0;
    this.family = 'IPv4';
    this.host = '0.0.0.0';
    this.port = 0;
    this.pending = 0;

    this.init();
  }

  fire(...args) {
    this.parent.emit(...args);
  }

  init() {
    this.parser.on('message', (data) => {
      const rinfo = {
        tcp: true,
        family: this.family,
        address: this.host,
        port: this.port
      };

      if (this.pending > 0)
        this.pending -= 1;

      this.fire('message', data, rinfo);
    });
  }

  bind() {
    this.socket.once('error', (err) => {
      if (!this.connected)
        return;

      this.fire('error', err);
      this.destroy();
    });

    this.socket.once('close', () => {
      if (!this.connected)
        return;

      this.destroy();
    });

    this.socket.on('drain', () => {
      if (!this.connected)
        return;

      this.buffered = 0;
    });

    this.socket.on('data', (data) => {
      if (!this.connected)
        return;

      this.parser.feed(data);
    });

    this.socket.setNoDelay(true);

    this.btimer = setInterval(() => this.timeout(), 5000);
  }

  timeout() {
    if (this.buffered > (2 << 20))
      this.destroy();
  }

  accept(socket) {
    this.socket = socket;
    this.connected = true;
    this.family = socket.remoteFamily;
    this.host = IP.normalize(socket.remoteAddress);
    this.port = socket.remotePort;
    this.bind();
    return this;
  }

  async connect(...args) {
    if (this.connected)
      return this;

    this.socket.connect(...args);
    this.socket.unref();

    return new Promise((resolve, reject) => {
      const cleanup = () => {
        if (this.ctimer != null) {
          clearTimeout(this.ctimer);
          this.ctimer = null;
        }
        // eslint-disable-next-line no-use-before-define
        this.socket.removeListener('error', onError);
      };

      const onError = (err) => {
        cleanup();
        reject(err);
      };

      this.socket.once('connect', () => {
        this.connected = true;
        this.family = this.socket.remoteFamily;
        this.host = IP.normalize(this.socket.remoteAddress);
        this.port = this.socket.remotePort;
        this.bind();

        cleanup();
        resolve(this);
      });

      this.socket.once('error', onError);

      this.ctimer = setTimeout(() => {
        this.ctimer = null;
        cleanup();
        reject(new Error('Connection timed out.'));
      }, 10000);
    });
  }

  cleanup() {
    if (!this.connected)
      return;

    if (this.ctimer != null) {
      clearInterval(this.ctimer);
      this.ctimer = null;
    }

    if (this.btimer != null) {
      clearInterval(this.btimer);
      this.btimer = null;
    }

    const key = IP.toHost(this.host, this.port);

    if (this.parent.sockets.get(key) === this)
      this.parent.sockets.delete(key);

    this.connected = false;
  }

  close() {
    if (!this.connected)
      return this;

    this.cleanup();
    this.socket.end();

    return this;
  }

  destroy() {
    if (this.destroyed)
      return this;

    this.destroyed = true;
    this.cleanup();
    this.socket.destroy();

    return this;
  }

  write(msg) {
    if (this.buffered > (5 << 20)) {
      this.destroy();
      return false;
    }

    const buf = Buffer.allocUnsafe(2);
    bio.writeU16BE(buf, msg.length, 0);

    this.socket.write(buf);
    this.pending += 1;

    return this.socket.write(msg);
  }

  static accept(parent, socket) {
    return new this(parent).accept(socket);
  }

  static connect(parent, ...args) {
    return new this(parent).connect(...args);
  }
}

/**
 * Parser
 * @extends EventEmitter
 */

class Parser extends EventEmitter {
  constructor() {
    super();
    this.pending = [];
    this.total = 0;
    this.waiting = 2;
    this.hasSize = false;
  }

  feed(data) {
    this.total += data.length;
    this.pending.push(data);

    while (this.total >= this.waiting) {
      const chunk = Buffer.allocUnsafe(this.waiting);

      let off = 0;

      while (off < chunk.length) {
        const len = this.pending[0].copy(chunk, off);
        if (len === this.pending[0].length)
          this.pending.shift();
        else
          this.pending[0] = this.pending[0].slice(len);
        off += len;
      }

      assert.strictEqual(off, chunk.length);

      this.total -= chunk.length;

      if (!this.hasSize) {
        this.waiting = bio.readU16BE(chunk, 0);
        this.hasSize = true;
        continue;
      }

      this.waiting = 2;
      this.hasSize = false;

      this.emit('message', chunk);
    }
  }
}

/*
 * Helpers
 */

function ensure4(host) {
  const ip = IP.toBuffer(host);

  if (IP.isIPv4(ip))
    return host;

  if (IP.isNull(ip))
    return '0.0.0.0';

  if (IP.isLocal(ip))
    return '127.0.0.1';

  return host;
}

function ensure6(host) {
  const ip = IP.toBuffer(host);

  if (!IP.isIPv4(ip))
    return host;

  return `::ffff:${IP.toString(ip)}`;
}

function normalize(options) {
  let type = hasIPv6 ? 'udp6' : 'udp4';

  if (options == null)
    return { type };

  if (typeof options === 'string') {
    assert(options === 'udp4' || options === 'udp6');
    return { type: options };
  }

  if (typeof options !== 'object')
    throw new Error('Invalid options object.');

  if (options.type != null) {
    assert(options.type === 'udp4' || options.type === 'udp6');
    type = options.type;
  } else if (options.inet6 != null) {
    assert(typeof options.inet6 === 'boolean');
    type = options.inet6 ? 'udp6' : 'udp4';
  }

  const opt = { type };

  if (options.reuseAddr != null)
    opt.reuseAddr = options.reuseAddr;

  if (options.recvBufferSize != null)
    opt.recvBufferSize = options.recvBufferSize;

  if (options.sendBufferSize != null)
    opt.sendBufferSize = options.sendBufferSize;

  return opt;
}

/*
 * Expose
 */

exports.Client = Client;
exports.Server = Server;
