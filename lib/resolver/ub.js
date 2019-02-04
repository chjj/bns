/*!
 * unbound.js - unbound dns resolver for bns
 * Copyright (c) 2018, Christopher Jeffrey (MIT License).
 * https://github.com/chjj/bns
 */

'use strict';

const assert = require('bsert');
const EventEmitter = require('events');
const Path = require('path');
const os = require('os');
const fs = require('bfile');
const IP = require('binet');
const Unbound = require('unbound');
const constants = require('../constants');
const encoding = require('../encoding');
const util = require('../util');
const wire = require('../wire');
const Cache = require('../cache');
const Hints = require('../hints');

const {
  MAX_UDP_SIZE,
  MAX_EDNS_SIZE
} = constants;

const {
  Message,
  Question,
  Record,
  opcodes,
  types
} = wire;

let defaultString = null;

/**
 * UnboundResolver
 * @extends EventEmitter
 */

class UnboundResolver extends EventEmitter {
  constructor(options) {
    super();

    this.inet6 = false;
    this.tcp = false;
    this.forceTCP = false;
    this.maxAttempts = 3;
    this.maxTimeout = 2000;
    this.rd = false;
    this.edns = false;
    this.ednsSize = MAX_EDNS_SIZE;
    this.dnssec = false;
    this.minimize = false;

    this.cache = new Cache();
    this.hints = new Hints();
    this.ub = new Unbound();
    this.hasStub = false;
    this.hintsFile = null;
    this.opened = false;

    this.initOptions(options);
  }

  initOptions(options) {
    if (options == null)
      return this;

    assert(options && typeof options === 'object');

    if (options.tcp != null) {
      assert(typeof options.tcp === 'boolean');
      this.tcp = options.tcp;
    }

    if (options.forceTCP != null) {
      assert(typeof options.forceTCP === 'boolean');
      if (options.forceTCP)
        this.tcp = true;
    }

    if (options.forceTCP != null) {
      assert(typeof options.forceTCP === 'boolean');
      this.forceTCP = options.forceTCP;
    }

    if (options.maxAttempts != null) {
      assert((options.maxAttempts >>> 0) === options.maxAttempts);
      this.maxAttempts = options.maxAttempts;
    }

    if (options.maxTimeout != null) {
      assert((options.maxTimeout >>> 0) === options.maxTimeout);
      this.maxTimeout = options.maxTimeout;
    }

    if (options.edns != null) {
      assert(typeof options.edns === 'boolean');
      this.edns = options.edns;
    }

    if (options.ednsSize != null) {
      assert((options.ednsSize >>> 0) === options.ednsSize);
      assert(options.ednsSize >= MAX_UDP_SIZE);
      assert(options.ednsSize <= MAX_EDNS_SIZE);
      this.ednsSize = options.ednsSize;
    }

    if (options.dnssec != null) {
      assert(typeof options.dnssec === 'boolean');
      this.dnssec = options.dnssec;
      if (this.dnssec)
        this.edns = true;
    }

    if (options.cache != null) {
      assert(options.cache instanceof Cache);
      this.cache = options.cache;
    }

    if (options.hints != null) {
      assert(options.hints instanceof Hints);
      this.hints = options.hints;
    }

    if (options.maxReferrals != null) {
      assert((options.maxReferrals >>> 0) === options.maxReferrals);
      this.maxReferrals = options.maxReferrals;
    }

    if (options.cacheSize != null) {
      assert((options.cacheSize >>> 0) === options.cacheSize);
      this.cache.maxSize = options.cacheSize;
    }

    if (options.minimize != null) {
      assert(typeof options.minimize === 'boolean');
      this.minimize = options.minimize;
    }

    return this;
  }

  setStub(host, port, ds) {
    assert(typeof host === 'string');
    assert((port & 0xffff) === port);
    assert(port !== 0);
    assert(ds instanceof Record);
    assert(ds.type === types.DS);

    const ip = IP.normalize(host);

    assert(!this.opened);
    assert(!this.hasStub);
    assert(!this.ub.finalized);

    this.ub.setOption('root-hints', null);
    this.ub.setStub('.', `${ip}@${port}`, false);
    this.ub.addTrustAnchor(ds.toString());
    this.hasStub = true;

    return this;
  }

  async open(...args) {
    assert(!this.opened);
    this.opened = true;

    if (this.ub.finalized)
      return;

    if (!this.hasStub) {
      if (!defaultString) {
        const h = new Hints();
        h.setDefault();
        defaultString = h.toHintString();
      }

      if (this.hints.ns.length === 0) {
        this.ub.setOption('root-hints', null);
      } else {
        const hints = this.hints.toHintString();

        if (hints !== defaultString) {
          const file = tempFile('hints');

          await fs.writeFile(file, hints);

          this.ub.setOption('root-hints', file);

          this.hintsFile = file;
        }
      }

      for (const ds of this.hints.anchors)
        this.ub.addTrustAnchor(ds.toString());
    }

    this.ub.setOption('logfile', null);
    this.ub.setOption('use-syslog', false);
    this.ub.tryOption('trust-anchor-signaling', false);
    this.ub.setOption('edns-buffer-size', this.ednsSize);
    this.ub.setOption('max-udp-size', this.ednsSize);
    this.ub.setOption('msg-cache-size', this.cache.maxSize);
    this.ub.setOption('key-cache-size', this.cache.maxSize);
    this.ub.setOption('neg-cache-size', this.cache.maxSize);
    this.ub.setOption('do-ip4', true);
    this.ub.setOption('do-ip6', this.inet6);
    this.ub.setOption('do-udp', !this.forceTCP);
    this.ub.setOption('do-tcp', this.tcp);
    this.ub.tryOption('qname-minimisation', this.minimize);
    this.ub.setOption('minimal-responses', false);

    if (this.hasStub) {
      try {
        this.ub.addZone('.', 'nodefault');
      } catch (e) {
        this.ub.addZone('.', 'transparent');
      }
    }
  }

  async close() {
    assert(this.opened);
    this.opened = false;

    this.ub = new Unbound();
    this.hasStub = false;

    if (this.hintsFile) {
      try {
        await fs.unlink(this.hintsFile);
      } catch (e) {
        ;
      }
      this.hintsFile = null;
    }
  }

  async resolve(qs) {
    assert(qs instanceof Question);

    if (!util.isName(qs.name))
      throw new Error('Invalid qname.');

    const result = await this.ub.resolve(qs.name, qs.type, qs.class);

    let msg;

    if (result.answerPacket) {
      msg = Message.decode(result.answerPacket);
    } else {
      msg = new Message();
      msg.id = 0;
      msg.opcode = opcodes.QUERY;
      msg.code = result.rcode;
      msg.qr = true;
      msg.ra = true;
      msg.ad = false;
      msg.question = [qs.clone()];
    }

    if (result.secure && !result.bogus)
      msg.ad = true;
    else
      msg.ad = false;

    return msg;
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
 * Static
 */

UnboundResolver.version = Unbound.version();
UnboundResolver.native = 2;

/*
 * Helpers
 */

function tempFile(name) {
  const rand = (Math.random() * 0x100000000) >>> 0;
  const pid = process.pid.toString(32);
  const now = Date.now().toString(32);
  const tag = rand.toString(32);
  const file = `${name}-${pid}-${now}-${tag}.zone`;

  return Path.resolve(os.tmpdir(), file);
}

/*
 * Expose
 */

module.exports = UnboundResolver;
