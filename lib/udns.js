/*!
 * udns.js - replacement dns node.js module (recursive)
 * Copyright (c) 2018, Christopher Jeffrey (MIT License).
 * https://github.com/chjj/bns
 */

'use strict';

const API = require('./api');
const Cache = require('./cache');
const Hints = require('./hints');
const UnboundResolver = require('./resolver/unbound');

let hints = null;
let ub = null;

const cache = new Cache();

function createResolver(options) {
  if (!hints)
    hints = Hints.fromRoot();

  const resolver = new UnboundResolver(options);

  if (!ub)
    ub = resolver.ub;

  if (!options.hints)
    resolver.hints = hints.clone();

  if (!options.cache)
    resolver.cache = cache;

  resolver.ub = ub;

  return resolver;
}

const api = API.make(createResolver, {
  tcp: true,
  edns: true,
  dnssec: true
});

api.version = UnboundResolver.version;
api.native = UnboundResolver.native;

module.exports = api;
