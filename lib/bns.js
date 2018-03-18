/*!
 * bns.js - dns module
 * Copyright (c) 2018, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bns
 */

'use strict';

const constants = require('./constants');
const dnssec = require('./dnssec');
const encoding = require('./encoding');
const hints = require('./hints');
const Hosts = require('./hosts');
const nsec3 = require('./nsec3');
const ResolvConf = require('./resolvconf');
const resolver = require('./resolver');
const server = require('./server');
const util = require('./util');
const wire = require('./wire');

exports.constants = constants;
exports.dnssec = dnssec;
exports.encoding = encoding;
exports.hints = hints;
exports.Hosts = Hosts;
exports.nsec3 = nsec3;
exports.ResolvConf = ResolvConf;

exports.DNSResolver = resolver.DNSResolver;
exports.StubResolver = resolver.StubResolver;
exports.RecursiveResolver = resolver.RecursiveResolver;
exports.Cache = resolver.Cache;
exports.Hints = resolver.Hints;
exports.Authority = resolver.Authority;

exports.DNSServer = server.DNSServer;
exports.StubServer = server.StubServer;
exports.RecursiveServer = server.RecursiveServer;

exports.util = util;
exports.wire = wire;
