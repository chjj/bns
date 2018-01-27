'use strict';

const wire = require('./wire');
const encoding = require('./encoding');
const DNSServer = require('./server');
const DNSResolver = require('./resolver');

exports.wire = wire;
exports.encoding = encoding;
exports.DNSServer = DNSServer;
exports.Server = DNSServer;
exports.DNSResolver = DNSResolver;
exports.Resolver = DNSResolver;
exports.server = (options) => new DNSServer(options);
exports.resolver = (options) => new DNSResolver(options);
