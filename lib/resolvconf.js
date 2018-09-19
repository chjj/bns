/*!
 * resolvconf.js - resolv.conf for bns
 * Copyright (c) 2018, Christopher Jeffrey (MIT License).
 * https://github.com/chjj/bns
 */

'use strict';

const assert = require('bsert');
const fs = require('bfile');
const IP = require('binet');
const {DNS_PORT} = require('./constants');
const util = require('./util');

/*
 * Constants
 */

const LOCAL_NS = [
  '127.0.0.1',
  '::1'
];

const GOOGLE_NS = [
  '8.8.8.8',
  '8.8.4.4',
  '2001:4860:4860::8888',
  '2001:4860:4860::8844'
];

const OPENDNS_NS = [
  '208.67.222.222',
  '208.67.220.220',
  '208.67.222.220',
  '208.67.220.222',
  '2620:0:ccc::2',
  '2620:0:ccd::2'
];

/**
 * ResolvConf
 */

class ResolvConf {
  constructor() {
    this.ns4 = [];
    this.ns6 = [];
    this.keys = new Map();
    this.domain = null;
    this.search = null;
    this.sortlist = [];
    this.debug = false;
    this.dots = 1;
    this.timeout = 5000;
    this.attempts = 2;
    this.rotate = false;
    this.checkNames = true;
    this.inet6 = false;
    this.byteString = false;
    this.dotInt = false;
    this.edns = false;
    this.singleRequest = false;
    this.singleRequestReopen = false;
    this.tldQuery = true;
    this.forceTCP = false;
  }

  inject(conf) {
    assert(conf instanceof this.constructor);

    this.ns4 = conf.ns4.slice();
    this.ns6 = conf.ns6.slice();

    this.keys.clear();

    for (const [key, pub] of conf.keys)
      this.keys.set(key, pub);

    this.domain = conf.domain;

    if (conf.search)
      this.search = conf.search.slice();
    else
      this.search = null;

    this.sortlist = conf.sortlist.slice();
    this.debug = conf.debug;
    this.dots = conf.dots;
    this.timeout = conf.timeout;
    this.attempts = conf.attempts;
    this.rotate = conf.rotate;
    this.checkNames = conf.checkNames;
    this.inet6 = conf.inet6;
    this.byteString = conf.byteString;
    this.dotInt = conf.dotInt;
    this.edns = conf.edns;
    this.singleRequest = conf.singleRequest;
    this.singleRequestReopen = conf.singleRequestReopen;
    this.tldQuery = conf.tldQuery;
    this.forceTCP = conf.forceTCP;

    return this;
  }

  clone() {
    const copy = new this.constructor();
    return copy.inject(this);
  }

  clear() {
    this.ns4.length = 0;
    this.ns6.length = 0;
    this.keys.clear();
    this.domain = null;
    this.search = null;
    this.sortlist = [];
    this.debug = false;
    this.dots = 1;
    this.timeout = 5000;
    this.attempts = 2;
    this.rotate = false;
    this.checkNames = true;
    this.inet6 = false;
    this.byteString = false;
    this.dotInt = false;
    this.edns = false;
    this.singleRequest = false;
    this.singleRequestReopen = false;
    this.tldQuery = true;
    this.forceTCP = false;
    return this;
  }

  getSystem() {
    if (process.platform === 'win32')
      return null;

    return '/etc/resolv.conf';
  }

  getRaw(inet6) {
    assert(typeof inet6 === 'boolean');

    const servers = [];

    for (const addr of this.ns4)
      servers.push(addr);

    if (inet6) {
      for (const addr of this.ns6)
        servers.push(addr);
    }

    return servers;
  }

  getServers() {
    const servers = [];

    for (const addr of this.ns4)
      servers.push(addr.hostname);

    for (const addr of this.ns6)
      servers.push(addr.hostname);

    return servers;
  }

  setServers(servers) {
    assert(Array.isArray(servers));

    this.clearServers();

    for (const server of servers)
      this.addServer(server);

    return this;
  }

  clearServers() {
    this.ns4.length = 0;
    this.ns6.length = 0;
    this.keys.clear();
    return this;
  }

  setDefault() {
    return this.setGoogle();
  }

  setLocal() {
    return this.setServers(LOCAL_NS);
  }

  setGoogle() {
    return this.setServers(GOOGLE_NS);
  }

  setOpenDNS() {
    return this.setServers(OPENDNS_NS);
  }

  addServer(server) {
    assert(typeof server === 'string');

    const addr = IP.fromHost(server, DNS_PORT);

    switch (addr.type) {
      case 4:
        this.ns4.push(addr);
        break;
      case 6:
        this.ns6.push(addr);
        break;
      default:
        throw new Error('Invalid address.');
    }

    if (addr.key)
      this.keys.set(addr.hostname, addr.key);
  }

  setDomain(domain) {
    assert(typeof domain === 'string');

    if (!util.isName(domain))
      throw new Error('Invalid domain.');

    this.search = null;
    this.domain = util.fqdn(domain);

    return this;
  }

  setSearch(list) {
    assert(typeof list === 'string');

    if (list.length > 256)
      throw new Error('Search list too large.');

    const names = util.splitSP(list);

    this.domain = null;
    this.search = [];

    for (const name of names) {
      if (!util.isName(name))
        continue;

      if (this.search.length === 6)
        throw new Error('Search list too large.');

      this.search.push(util.fqdn(name));
    }

    return this;
  }

  setSort(list) {
    assert(typeof list === 'string');

    const pairs = util.splitSP(list);

    for (const pair of pairs) {
      const items = pair.split('/', 3);

      let ip = items[0];
      let mask = null;

      if (items.length > 1)
        mask = items[1];

      try {
        ip = IP.normalize(ip);
        if (mask)
          mask = IP.normalize(mask);
      } catch (e) {
        continue;
      }

      if (this.sortlist.length === 10)
        throw new Error('Sort list too large.');

      this.sortlist.push({ ip, mask });
    }

    return this;
  }

  toString(full) {
    if (full == null)
      full = false;

    assert(typeof full === 'boolean');

    let out = '';

    out += '# Generated by bns\n';

    for (const addr of this.getRaw(true)) {
      out += 'nameserver ';

      if (full)
        out += IP.toHost(addr.host, addr.port, addr.key);
      else
        out += addr.host;

      out += '\n';
    }

    if (this.domain)
      out += `domain ${util.trimFQDN(this.domain)}\n`;

    if (this.search) {
      for (const host of this.search)
        out += `search ${util.trimFQDN(host)}\n`;
    }

    if (this.sortlist.length > 0) {
      out += 'sortlist';
      for (const {ip, mask} of this.sortlist) {
        if (mask)
          out += ` ${ip}/${mask}`;
        else
          out += ` ${ip}`;
      }
      out += '\n';
    }

    out += 'options';

    if (this.debug)
      out += ' debug';

    if (this.dots !== 1)
      out += ` ndots:${this.dots}`;

    if (Math.ceil(this.timeout / 1000) !== 5)
      out += ` timeout:${Math.ceil(this.timeout / 1000)}`;

    if (this.attempts !== 2)
      out += ` attempts:${this.attempts}`;

    if (this.rotate)
      out += ' rotate';

    if (!this.checkNames)
      out += ' no-check-names';

    if (this.inet6)
      out += ' inet6';

    if (this.byteString)
      out += ' ip6-bytestring';

    if (this.dotInt)
      out += ' ip6-dotint';

    if (this.edns)
      out += ' edns0';

    if (this.singleRequest)
      out += ' single-request';

    if (this.singleRequestReopen)
      out += ' single-request-reopen';

    if (!this.tldQuery)
      out += ' no-tld-query';

    if (this.forceTCP)
      out += ' use-vc';

    out += '\n';

    if (out.slice(-8) === 'options\n')
      out = out.slice(0, -8);

    return out;
  }

  parseServer(text) {
    assert(typeof text === 'string');

    const server = text.trim().toLowerCase();

    try {
      return this.addServer(server);
    } catch (e) {
      return this;
    }
  }

  parseDomain(text) {
    assert(typeof text === 'string');

    const domain = text.trim().toLowerCase();

    try {
      return this.setDomain(domain);
    } catch (e) {
      return this;
    }
  }

  parseSearch(text) {
    assert(typeof text === 'string');

    const list = text.trim().toLowerCase();

    try {
      return this.setSearch(list);
    } catch (e) {
      return this;
    }
  }

  parseSort(text) {
    assert(typeof text === 'string');

    const list = text.trim().toLowerCase();

    try {
      return this.setSort(list);
    } catch (e) {
      return this;
    }
  }

  parseOptions(line) {
    assert(typeof line === 'string');

    const options = util.splitSP(line);

    for (const option of options) {
      const i = option.indexOf(':');

      let name = null;
      let arg = '';

      if (i !== -1) {
        name = option.substring(0, i);
        arg = option.substring(i + 1);
      } else {
        arg = option;
        name = arg;
      }

      name = name.toLowerCase();

      switch (name) {
        case 'debug': {
          this.debug = true;
          break;
        }
        case 'ndots': {
          try {
            this.dots = Math.min(15, util.parseU8(arg));
            this.dots = Math.max(1, this.dots);
          } catch (e) {
            continue;
          }
          break;
        }
        case 'timeout': {
          try {
            this.timeout = Math.min(30, util.parseU8(arg));
            this.timeout = Math.max(1, this.timeout);
            this.timeout *= 1000;
          } catch (e) {
            continue;
          }
          break;
        }
        case 'attempts': {
          try {
            this.attempts = Math.min(5, util.parseU8(arg));
            this.attempts = Math.max(1, this.attempts);
          } catch (e) {
            continue;
          }
          break;
        }
        case 'rotate': {
          this.rotate = true;
          break;
        }
        case 'no-check-names': {
          this.checkNames = false;
          break;
        }
        case 'inet6': {
          this.inet6 = true;
          break;
        }
        case 'ip6-bytestring': {
          this.byteString = true;
          break;
        }
        case 'ip6-dotint': {
          this.dotInt = true;
          break;
        }
        case 'no-ip6-dotint': {
          this.dotInt = false;
          break;
        }
        case 'edns0': {
          this.edns = true;
          break;
        }
        case 'single-request': {
          this.singleRequest = true;
          break;
        }
        case 'single-request-reopen': {
          this.singleRequestReopen = true;
          break;
        }
        case 'no-tld-query': {
          this.tldQuery = false;
          break;
        }
        case 'use-vc': {
          this.forceTCP = true;
          break;
        }
      }
    }

    return this;
  }

  fromString(text) {
    assert(typeof text === 'string');

    this.clearServers();

    const lines = util.splitLines(text, true);

    for (const line of lines) {
      if (line[0] === '#' || line[0] === ';')
        continue;

      const i = line.indexOf(' ');

      if (i === -1)
        continue;

      const option = line.substring(0, i).toLowerCase();
      const rest = line.substring(i + 1);

      switch (option) {
        case 'nameserver': {
          this.parseServer(rest);
          break;
        }
        case 'domain': {
          this.parseDomain(rest);
          break;
        }
        case 'search': {
          this.parseSearch(rest);
          break;
        }
        case 'sortlist': {
          this.parseSort(rest);
          break;
        }
        case 'options':
          this.parseOptions(rest);
          break;
      }
    }

    return this;
  }

  static fromString(text) {
    return new this().fromString(text);
  }

  readEnv() {
    if (process.env.LOCALDOMAIN)
      this.parseDomain(process.env.LOCALDOMAIN);

    if (process.env.RES_OPTIONS)
      this.parseOptions(process.env.RES_OPTIONS);

    return this;
  }

  fromFile(file) {
    assert(typeof file === 'string');
    const text = fs.readFileSync(file, 'utf8');
    return this.fromString(text);
  }

  static fromFile(file) {
    return new this().fromFile(file);
  }

  fromSystem() {
    const file = this.getSystem();

    if (file) {
      try {
        this.fromFile(file);
      } catch (e) {
        this.setDefault();
      }
    } else {
      this.setDefault();
    }

    this.readEnv();

    return this;
  }

  static fromSystem() {
    return new this().fromSystem();
  }

  async fromFileAsync(file) {
    assert(typeof file === 'string');
    const text = await fs.readFile(file, 'utf8');
    return this.fromString(text);
  }

  static fromFileAsync(file) {
    return new this().fromFileAsync(file);
  }

  async fromSystemAsync() {
    const file = this.getSystem();

    if (file) {
      try {
        await this.fromFileAsync(file);
      } catch (e) {
        this.setDefault();
      }
    } else {
      this.setDefault();
    }

    this.readEnv();

    return this;
  }

  static fromSystemAsync() {
    return new this().fromSystemAsync();
  }
}

/*
 * Expose
 */

module.exports = ResolvConf;
