/*!
 * lazy.js - lazy require for bns
 * Copyright (c) 2018, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bns
 */

'use strict';

const assert = require('assert');

/*
 * Lazy Require
 */

function lazy(require, name) {
  assert(typeof name === 'string');
  return require(name);
}

/*
 * Expose
 */

module.exports = lazy;
