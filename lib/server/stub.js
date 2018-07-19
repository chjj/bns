/*!
 * stub.js - stub dns server for bns
 * Copyright (c) 2018, Christopher Jeffrey (MIT License).
 * https://github.com/chjj/bns
 */

'use strict';

const DNSServer = require('./dns');
const StubResolver = require('../resolver/stub');

/**
 * StubServer
 * @extends EventEmitter
 */

class StubServer extends DNSServer {
  constructor(options) {
    super(options);
    this.resolver = new StubResolver(options);
    this.resolver.on('log', (...args) => this.emit('log', ...args));
    this.resolver.on('error', err => this.emit('error', err));
    this.ra = true;
    this.initOptions(options);
  }

  getServers() {
    return this.resolver.getServers();
  }

  setServers(servers) {
    this.resolver.setServers(servers);
    return this;
  }

  get conf() {
    return this.resolver.conf;
  }

  set conf(value) {
    this.resolver.conf = value;
  }

  get hosts() {
    return this.resolver.hosts;
  }

  set hosts(value) {
    this.resolver.hosts = value;
  }
}

/*
 * Expose
 */

module.exports = StubServer;
