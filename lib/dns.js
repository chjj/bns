/*!
 * dns.js - replacement dns node.js module
 * Copyright (c) 2018, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bns
 */

'use strict';

const API = require('./api');
const {StubResolver} = require('./resolver');
const Hosts = require('./hosts');
const ResolvConf = require('./resolvconf');

let conf = null;
let hosts = null;

function createResolver(options) {
  if (!conf)
    conf = ResolvConf.fromSystem();

  if (!hosts)
    hosts = Hosts.fromSystem();

  const resolver = new StubResolver(options);

  if (!options.conf)
    resolver.conf = conf.clone();

  if (!options.hosts)
    resolver.hosts = hosts.clone();

  return resolver;
}

module.exports = new API(createResolver, {
  edns: false,
  dnssec: false
});
