/*!
 * authority.js - authority object for bns
 * Copyright (c) 2018, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bns
 *
 * Parts of this software are based on solvere:
 *   https://github.com/rolandshoemaker/solvere
 */

'use strict';

const assert = require('assert');

/**
 * Authority
 */

class Authority {
  constructor(name, host, zone) {
    assert(name == null || typeof name === 'string');
    assert(host == null || typeof host === 'string');
    assert(zone == null || typeof zone === 'string');

    this.name = name || '.';
    this.host = host || '0.0.0.0';
    this.port = 53;
    this.zone = zone || '.';
  }

  inject(auth) {
    assert(auth instanceof this.constructor);
    this.name = auth.name;
    this.host = auth.host;
    this.port = auth.port;
    this.zone = auth.zone;
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
