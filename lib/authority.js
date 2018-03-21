/*!
 * authority.js - authority object for bns
 * Copyright (c) 2018, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bns
 *
 * Parts of this software are based on solvere:
 *   https://github.com/rolandshoemaker/solvere
 */

'use strict';

/**
 * Authority
 */

class Authority {
  constructor(name, host, zone) {
    this.name = name || '.';
    this.host = host || '0.0.0.0';
    this.port = 53;
    this.zone = zone || '.';
  }
}

/*
 * Expose
 */

module.exports = Authority;
