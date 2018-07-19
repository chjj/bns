/*!
 * authority.js - authority object for bns
 * Copyright (c) 2018, Christopher Jeffrey (MIT License).
 * https://github.com/chjj/bns
 *
 * Parts of this software are based on solvere:
 *   https://github.com/rolandshoemaker/solvere
 */

'use strict';

const assert = require('bsert');

/**
 * Authority
 */

class Authority {
  constructor(zone, name) {
    assert(zone == null || typeof zone === 'string');
    assert(name == null || typeof name === 'string');

    this.zone = zone || '.';
    this.name = name || '.';
    this.servers = [];
  }

  add(host, port) {
    assert(typeof host === 'string');
    assert((port & 0xffff) === port);
    this.servers.push({ host, port });
    return this;
  }

  inject(auth) {
    assert(auth instanceof this.constructor);
    this.zone = auth.zone;
    this.name = auth.name;
    this.servers = auth.servers.slice();
    return this;
  }

  clone() {
    const copy = new this.constructor();
    return copy.inject(this);
  }
}

/*
 * Expose
 */

module.exports = Authority;
