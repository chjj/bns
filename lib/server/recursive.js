/*!
 * recursive.js - recursive dns server for bns
 * Copyright (c) 2018, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bns
 */

'use strict';

const DNSServer = require('./dns');
const dnssec = require('../dnssec');
const RecursiveResolver = require('../resolver/recursive');

/**
 * RecursiveServer
 * @extends EventEmitter
 */

class RecursiveServer extends DNSServer {
  constructor(options) {
    super(options);
    this.resolver = new RecursiveResolver(options);
    this.resolver.on('log', (...args) => this.emit('log', ...args));
    this.resolver.on('error', err => this.emit('error', err));
    this.ra = true;
    this.initOptions(options);
  }

  get cache() {
    return this.resolver.cache;
  }

  set cache(value) {
    this.resolver.cache = value;
  }

  get hints() {
    return this.resolver.hints;
  }

  set hints(value) {
    this.resolver.hints = value;
  }

  async resolve(req, rinfo) {
    const [qs] = req.question;
    const res = await this.resolver.resolve(qs);

    if (!this.dnssec || !req.isDNSSEC())
      dnssec.filterMessage(res, qs.type);

    return res;
  }
}

/*
 * Expose
 */

module.exports = RecursiveServer;
