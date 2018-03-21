/*!
 * rdns.js - replacement dns node.js module (recursive)
 * Copyright (c) 2018, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bns
 */

'use strict';

const API = require('./api');
const {RecursiveResolver} = require('./resolver');

function createResolver(options, conf, hosts) {
  const resolver = new RecursiveResolver(options);
  return resolver;
}

module.exports = new API(createResolver, {
  edns: true,
  dnssec: true
});
