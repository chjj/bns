/*!
 * bns.js - dns module
 * Copyright (c) 2018, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bns
 */

'use strict';

const wire = require('./wire');
const encoding = require('./encoding');
const server = require('./server');
const resolver = require('./resolver');

exports.wire = wire;
exports.encoding = encoding;
exports.DNSServer = server.DNSServer;
exports.StubServer = server.StubServer;
exports.RecursiveServer = server.RecursiveServer;
exports.DNSResolver = resolver.DNSResolver;
exports.StubResolver = resolver.StubResolver;
exports.RecursiveResolver = resolver.RecursiveResolver;
