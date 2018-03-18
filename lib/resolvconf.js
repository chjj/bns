/*!
 * resolvconf.js - resolv.conf for bns
 * Copyright (c) 2018, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bns
 */

'use strict';

const assert = require('assert');
const fs = require('bfile');
const IP = require('binet');
const util = require('./util');

/*
 * Constants
 */

const OPENDNS_NS = [
  '208.67.222.222',
  '208.67.220.220',
  '208.67.222.220',
  '208.67.220.222',
  '2620:0:ccc::2',
  '2620:0:ccd::2'
];

const GOOGLE_NS = [
  '8.8.8.8',
  '8.8.4.4',
  '2001:4860:4860::8888',
  '2001:4860:4860::8844'
];

// Make eslint happy.
OPENDNS_NS;

/**
 * ResolvConf
 */

class ResolvConf {
  constructor() {
    this.ns4 = [];
    this.ns6 = [];
    this.domain = null;
    this.search = null;
    this.sortlist = [];
    this.debug = false;
    this.dots = 1;
    this.timeout = 5;
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
    this.init();
  }

  init() {
    return this.setServers(GOOGLE_NS);
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
    return this;
  }

  randomServer(inet6) {
    if (inet6 && this.ns6.length > 0)
      return util.randomItem(this.ns6);

    if (this.ns4.length === 0)
      throw new Error('No servers available.');

    return util.randomItem(this.ns4);
  }

  addServer(server) {
    assert(typeof server === 'string');

    const addr = IP.fromHost(server, 53);

    if (addr.type === 4)
      this.ns4.push(addr);
    else if (addr.type === 6)
      this.ns6.push(addr);
    else
      throw new Error('Invalid address.');
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

    const names = list.split(/\s+/);

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

    const pairs = list.split(/\s+/);

    for (const pair of pairs) {
      const items = pair.split('/');

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

    line = line.trim();
    line = line.toLowerCase();

    const options = line.split(/\s+/);

    for (const option of options) {
      const i = option.indexOf(':');

      let name = null;
      let arg = '';

      if (i !== -1) {
        name = option.substring(0, i);
        arg = option.substring(i + 1);
      } else {
        name = arg;
      }

      switch (name) {
        case 'debug': {
          this.debug = true;
          break;
        }
        case 'ndots': {
          try {
            this.dots = Math.min(15, util.parseU8(arg));
          } catch (e) {
            continue;
          }
          break;
        }
        case 'timeout': {
          try {
            this.timeout = Math.min(30, util.parseU8(arg));
          } catch (e) {
            continue;
          }
          break;
        }
        case 'attempts': {
          try {
            this.attempts = Math.min(5, util.parseU8(arg));
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

    if (text.charCodeAt(0) === 0xfeff)
      text = text.substring(1);

    text = text.replace(/\t/g, ' ');
    text = text.replace(/\r\n/g, '\n');
    text = text.replace(/\r/g, '\n');
    text = text.replace(/\\\n/g, '');

    for (const chunk of text.split('\n')) {
      const line = chunk.trim();

      if (line.length === 0)
        continue;

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

  fromFile(file) {
    let text;

    this.init();

    try {
      text = fs.readFileSync(file, 'utf8');
    } catch (e) {
      return this;
    }

    return this.fromString(text);
  }

  static fromFile(file) {
    return new this().fromFile(file);
  }

  fromSystem() {
    if (process.platform === 'win32')
      return this.init();

    this.fromFile('/etc/resolv.conf');

    if (process.env.LOCALDOMAIN)
      this.parseDomain(process.env.LOCALDOMAIN);

    if (process.env.RES_OPTIONS)
      this.parseOptions(process.env.RES_OPTIONS);

    return this;
  }

  static fromSystem() {
    return new this().fromSystem();
  }
}

/*
 * Expose
 */

module.exports = ResolvConf;
