/*!
 * lazy.js - lazy require for bns
 * Copyright (c) 2018, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bns
 */

'use strict';

const assert = require('assert');

let iana = null;
let scan = null;
let schema = null;

/*
 * Lazy Require
 */

function lazy(require, name) {
  assert(typeof name === 'string');

  switch (name) {
    case './iana':
      if (!iana)
        iana = require('./iana');
      return iana;
    case './scan':
      if (!scan)
        scan = require('./scan');
      return scan;
    case './schema':
      if (!schema)
        schema = require('./schema');
      return schema;
  }

  throw new Error(`Unknown module: ${name}.`);
}

/*
 * Expose
 */

module.exports = lazy;
