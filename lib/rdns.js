/*!
 * rdns.js - replacement dns node.js module (recursive)
 * Copyright (c) 2018, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bns
 */

'use strict';

const API = require('./api');
const {RecursiveResolver, Hints, Cache} = require('./resolver');

let hints = null;

const cache = new Cache();

function createResolver(options) {
  if (!hints)
    hints = Hints.fromRoot();

  const resolver = new RecursiveResolver(options);

  if (!options.hints)
    resolver.hints = hints.clone();

  if (!options.cache)
    resolver.cache = cache;

  return resolver;
}

module.exports = new API(createResolver, {
  edns: true,
  dnssec: true
});
