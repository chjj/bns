/*!
 * stub.js - stub dns resolver for bns
 * Copyright (c) 2018, Christopher Jeffrey (MIT License).
 * https://github.com/chjj/bns
 */

'use strict';

const assert = require('bsert');
const constants = require('../constants');
const DNSResolver = require('./dns');
const encoding = require('../encoding');
const Hosts = require('../hosts');
const ResolvConf = require('../resolvconf');
const util = require('../util');
const wire = require('../wire');
const {MAX_EDNS_SIZE} = constants;

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
    this.cd = false;
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
      if (Array.isArray(options.hosts)) {
        this.hosts.setHosts(options.hosts);
      } else {
        assert(options.hosts instanceof Hosts);
        this.hosts = options.hosts;
      }
    }

    if (options.rd != null) {
      assert(typeof options.rd === 'boolean');
      this.rd = options.rd;
    }

    if (options.cd != null) {
      assert(typeof options.cd === 'boolean');
      this.cd = options.cd;
    }

    if (options.servers != null) {
      assert(Array.isArray(options.servers));
      this.conf.setServers(options.servers);
    }

    return this;
  }

  getRaw() {
    return this.conf.getRaw(this.inet6);
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

  async resolve(qs) {
    assert(qs instanceof Question);

    const {name, type} = qs;
    const answer = this.hosts.query(name, type);

    if (answer) {
      const res = new Message();

      res.id = util.id();
      res.opcode = opcodes.QUERY;
      res.code = codes.NOERROR;
      res.qr = true;
      res.rd = true;
      res.ra = true;
      res.ad = true;
      res.question = [qs];
      res.answer = answer;

      if (this.edns)
        res.setEDNS(MAX_EDNS_SIZE, this.dnssec);

      return res;
    }

    return this.query(qs, this.getRaw());
  }

  async lookup(name, type) {
    const qs = new Question(name, type);
    return this.resolve(qs);
  }

  async reverse(addr) {
    const name = encoding.reverse(addr);
    return this.lookup(name, types.PTR);
  }
}

/*
 * Expose
 */

module.exports = StubResolver;
