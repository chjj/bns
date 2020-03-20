/*!
 * bns.js - dns module
 * Copyright (c) 2018, Christopher Jeffrey (MIT License).
 * https://github.com/chjj/bns
 */

'use strict';

exports.API = require('./api');
exports.Authority = require('./authority');
exports.AuthServer = require('./server/auth');
exports.Cache = require('./cache');
exports.constants = require('./constants');
exports.dane = require('./dane');
exports.dns = require('./dns');
exports.DNSResolver = require('./resolver/dns');
exports.DNSServer = require('./server/dns');
exports.dnssec = require('./dnssec');
exports.encoding = require('./encoding');
exports.DNSError = require('./error');
exports.Hints = require('./hints');
exports.Hosts = require('./hosts');
exports.hsig = require('./hsig');
exports.nsec3 = require('./nsec3');
exports.openpgpkey = require('./openpgpkey');
exports.Ownership = require('./ownership');
exports.punycode = require('./punycode');
exports.rdns = require('./rdns');
exports.RecursiveResolver = require('./resolver/recursive');
exports.RecursiveServer = require('./server/recursive');
exports.ResolvConf = require('./resolvconf');
exports.ROOT_HINTS = require('./roothints');
exports.RootResolver = require('./resolver/root');
exports.sig0 = require('./sig0');
exports.smimea = require('./smimea');
exports.srv = require('./srv');
exports.sshfp = require('./sshfp');
exports.StubResolver = require('./resolver/stub');
exports.StubServer = require('./server/stub');
exports.tlsa = require('./tlsa');
exports.tsig = require('./tsig');
exports.udns = require('./udns');
exports.UnboundResolver = require('./resolver/unbound');
exports.UnboundServer = require('./server/unbound');
exports.util = require('./util');
exports.wire = require('./wire');
exports.Zone = require('./zone');

exports.version = '0.11.0';
exports.unbound = exports.UnboundResolver.version;
exports.native = exports.UnboundResolver.native;
