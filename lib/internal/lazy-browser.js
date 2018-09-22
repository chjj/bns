/*!
 * lazy.js - lazy require for bns
 * Copyright (c) 2018, Christopher Jeffrey (MIT License).
 * https://github.com/chjj/bns
 */

'use strict';

const assert = require('bsert');
const iana = require('./iana');
const scan = require('./scan');
const schema = require('./schema');

/*
 * Lazy Require
 */

function lazy(name) {
  assert(typeof name === 'string');

  switch (name) {
    case './iana':
    case './internal/iana':
      return iana;
    case './scan':
    case './internal/scan':
      return scan;
    case './schema':
    case './internal/schema':
      return schema;
  }

  throw new Error(`Unknown module: ${name}.`);
}

/*
 * Expose
 */

module.exports = lazy;
