/*!
 * stub.js - stub dns resolver for bns
 * Copyright (c) 2018, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bns
 */

'use strict';

const assert = require('assert');
const DNSResolver = require('./dns');
const encoding = require('../encoding');
const Hosts = require('../hosts');
const ResolvConf = require('../resolvconf');
const util = require('../util');
const wire = require('../wire');
const {id} = util;

const {
  Message,
  Question,
  opcodes,
  types,
  codes
} = wire;

/**
 * StubResolver
 * @extends DNSResolver
 */

class StubResolver extends DNSResolver {
  constructor(options) {
    super(options);

    this.rd = true;
    this.conf = new ResolvConf();
    this.hosts = new Hosts();

    this.initOptions(options);
  }

  initOptions(options) {
    if (options == null)
      return this;

    this.parseOptions(options);

    if (options.conf != null) {
      assert(options.conf instanceof ResolvConf);
      this.conf = options.conf;
    }

    if (options.hosts != null) {
      assert(options.hosts instanceof Hosts);
      this.hosts = options.hosts;
    }

    return this;
  }

  getServers() {
    return this.conf.getServers();
  }

  setServers(servers) {
    this.conf.setServers(servers);
    return this;
  }

  getHosts() {
    return this.hosts.getHosts();
  }

  setHosts(hosts) {
    this.hosts.setHosts(hosts);
    return this;
  }

  randomServer() {
    return this.conf.randomServer(this.inet6);
  }

  async resolve(qs, port, host) {
    assert(qs instanceof Question);
    assert(port == null || typeof port === 'number');
    assert(host == null || typeof host === 'string');

    const {name, type} = qs;
    const answer = this.hosts.query(name, type);

    if (answer) {
      const res = new Message();

      res.id = id();
      res.opcode = opcodes.QUERY;
      res.code = codes.NOERROR;
      res.qr = true;
      res.rd = true;
      res.ra = true;
      res.ad = true;
      res.question = [qs];
      res.answer = answer;

      if (this.edns)
        res.setEDNS(4096, this.dnssec);

      return res;
    }

    if (host == null) {
      const addr = this.randomServer();

      host = addr.host;

      if (port == null)
        port = addr.port;
    }

    if (port == null)
      port = 53;

    return this.query(qs, port, host);
  }

  async lookup(name, type, port, host) {
    const qs = new Question(name, type);
    return this.resolve(qs, port, host);
  }

  async reverse(addr, port, host) {
    const name = encoding.reverse(addr);
    return this.lookup(name, types.PTR, port, host);
  }
}

/*
 * Expose
 */

module.exports = StubResolver;
