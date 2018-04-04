/*!
 * lazy.js - lazy require for bns
 * Copyright (c) 2018, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bns
 */

'use strict';

const assert = require('assert');
const iana = require('./iana');

/*
 * Lazy Require
 */

function lazy(_, name) {
  assert(typeof name === 'string');

  switch (name) {
    case './iana':
      return iana;
  }

  throw new Error(`Unknown module: ${name}.`);
}

/*
 * Expose
 */

module.exports = lazy;
