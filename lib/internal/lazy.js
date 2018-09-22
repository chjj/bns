/*!
 * lazy.js - lazy require for bns
 * Copyright (c) 2018, Christopher Jeffrey (MIT License).
 * https://github.com/chjj/bns
 */

'use strict';

const assert = require('bsert');

let iana = null;
let scan = null;
let schema = null;

/*
 * Lazy Require
 */

function lazy(name) {
  assert(typeof name === 'string');

  switch (name) {
    case './iana':
    case './internal/iana': {
      if (!iana)
        iana = require('./iana');
      return iana;
    }
    case './scan':
    case './internal/scan': {
      if (!scan)
        scan = require('./scan');
      return scan;
    }
    case './schema':
    case './internal/schema': {
      if (!schema)
        schema = require('./schema');
      return schema;
    }
  }

  throw new Error(`Unknown module: ${name}.`);
}

/*
 * Expose
 */

module.exports = lazy;
