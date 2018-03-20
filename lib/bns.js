/*!
 * bns.js - dns module
 * Copyright (c) 2018, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bns
 */

'use strict';

const api = require('./api');
const constants = require('./constants');
const dane = require('./dane');
const dnssec = require('./dnssec');
const encoding = require('./encoding');
const hints = require('./hints');
const Hosts = require('./hosts');
const hsig = require('./hsig');
const nsec3 = require('./nsec3');
const ResolvConf = require('./resolvconf');
const resolver = require('./resolver');
const server = require('./server');
const sig0 = require('./sig0');
const smimea = require('./smimea');
const sshfp = require('./sshfp');
const tlsa = require('./tlsa');
const util = require('./util');
const wire = require('./wire');

exports.api = api;
exports.constants = constants;
exports.dane = dane;
exports.dnssec = dnssec;
exports.encoding = encoding;
exports.hints = hints;
exports.Hosts = Hosts;
exports.hsig = hsig;
exports.nsec3 = nsec3;
exports.ResolvConf = ResolvConf;

exports.DNSResolver = resolver.DNSResolver;
exports.StubResolver = resolver.StubResolver;
exports.OSResolver = resolver.OSResolver;
exports.RecursiveResolver = resolver.RecursiveResolver;
exports.Cache = resolver.Cache;
exports.Hints = resolver.Hints;
exports.Authority = resolver.Authority;

exports.DNSServer = server.DNSServer;
exports.StubServer = server.StubServer;
exports.RecursiveServer = server.RecursiveServer;

exports.sig0 = sig0;
exports.smimea = smimea;
exports.sshfp = sshfp;
exports.tlsa = tlsa;
exports.util = util;
exports.wire = wire;
