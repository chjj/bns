/*!
 * unbound.js - unbound dns resolver for bns
 * Copyright (c) 2018, Christopher Jeffrey (MIT License).
 * https://github.com/chjj/bns
 */

'use strict';

try {
  module.exports = require('./ub');
} catch (e) {
  module.exports = require('./recursive');
}
