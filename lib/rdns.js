/*!
 * rdns.js - replacement dns node.js module (recursive)
 * Copyright (c) 2018, Christopher Jeffrey (MIT License).
 * https://github.com/chjj/bns
 */

'use strict';

const API = require('./api');
const Cache = require('./cache');
const Hints = require('./hints');
const RecursiveResolver = require('./resolver/recursive');

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

module.exports = API.make(createResolver, {
  tcp: true,
  edns: true,
  dnssec: true
});
