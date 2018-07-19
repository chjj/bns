/*!
 * lazy.js - lazy require for bns
 * Copyright (c) 2018, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bns
 */

'use strict';

const assert = require('bsert');
const iana = require('./iana');
const scan = require('./scan');
const schema = require('./schema');

/*
 * Lazy Require
 */

function lazy(_, name) {
  assert(typeof name === 'string');

  switch (name) {
    case './iana':
      return iana;
    case './scan':
      return scan;
    case './schema':
      return schema;
  }

  throw new Error(`Unknown module: ${name}.`);
}

/*
 * Expose
 */

module.exports = lazy;
