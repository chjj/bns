/*!
 * dns.js - replacement dns node.js module
 * Copyright (c) 2018, Christopher Jeffrey (MIT License).
 * https://github.com/chjj/bns
 */

'use strict';

const API = require('./api');
const Hosts = require('./hosts');
const ResolvConf = require('./resolvconf');
const StubResolver = require('./resolver/stub');

let conf = null;
let hosts = null;

function createResolver(options, servers) {
  if (!conf)
    conf = ResolvConf.fromSystem();

  if (!hosts)
    hosts = Hosts.fromSystem();

  const resolver = new StubResolver(options);

  if (!options.conf)
    resolver.conf = conf.clone();

  if (!options.hosts)
    resolver.hosts = hosts.clone();

  if (servers)
    resolver.setServers(servers);

  return resolver;
}

module.exports = API.make(createResolver, {
  tcp: true,
  edns: false,
  dnssec: false
});
