/*!
 * bns.js - dns module
 * Copyright (c) 2018, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bns
 */

'use strict';

const API = require('./api');
const Authority = require('./authority');
const AuthServer = require('./server/auth');
const Cache = require('./cache');
const constants = require('./constants');
const dane = require('./dane');
const dns = require('./dns');
const DNSResolver = require('./resolver/dns');
const DNSServer = require('./server/dns');
const dnssec = require('./dnssec');
const encoding = require('./encoding');
const DNSError = require('./error');
const Hints = require('./hints');
const Hosts = require('./hosts');
const hsig = require('./hsig');
const nsec3 = require('./nsec3');
const openpgpkey = require('./openpgpkey');
const rdns = require('./rdns');
const RecursiveResolver = require('./resolver/recursive');
const RecursiveServer = require('./server/recursive');
const ResolvConf = require('./resolvconf');
const ROOT_HINTS = require('./roothints');
const sig0 = require('./sig0');
const smimea = require('./smimea');
const srv = require('./srv');
const sshfp = require('./sshfp');
const StubResolver = require('./resolver/stub');
const StubServer = require('./server/stub');
const tlsa = require('./tlsa');
const tsig = require('./tsig');
const util = require('./util');
const wire = require('./wire');
const Zone = require('./zone');

exports.API = API;
exports.Authority = Authority;
exports.AuthServer = AuthServer;
exports.Cache = Cache;
exports.constants = constants;
exports.dane = dane;
exports.dns = dns;
exports.DNSResolver = DNSResolver;
exports.DNSServer = DNSServer;
exports.dnssec = dnssec;
exports.encoding = encoding;
exports.DNSError = DNSError;
exports.Hints = Hints;
exports.Hosts = Hosts;
exports.hsig = hsig;
exports.nsec3 = nsec3;
exports.openpgpkey = openpgpkey;
exports.rdns = rdns;
exports.RecursiveResolver = RecursiveResolver;
exports.RecursiveServer = RecursiveServer;
exports.ResolvConf = ResolvConf;
exports.ROOT_HINTS = ROOT_HINTS;
exports.sig0 = sig0;
exports.smimea = smimea;
exports.srv = srv;
exports.sshfp = sshfp;
exports.StubResolver = StubResolver;
exports.StubServer = StubServer;
exports.tlsa = tlsa;
exports.tsig = tsig;
exports.util = util;
exports.wire = wire;
exports.Zone = Zone;
