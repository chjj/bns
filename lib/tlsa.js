/*!
 * tlsa.js - TLSA for bns
 * Copyright (c) 2018, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bns
 *
 * Parts of this software are based on miekg/dns:
 *   https://github.com/miekg/dns/blob/master/tlsa.go
 */

'use strict';

const assert = require('assert');
const dane = require('./dane');
const util = require('./util');
const wire = require('./wire');
const {types, classes, Record, TLSARecord} = wire;
const tlsa = exports;

/*
 * Constants
 */

const DUMMY = Buffer.alloc(0);

/*
 * TLSA
 */

tlsa.create = function create(cert, name, protocol, port, options = {}) {
  assert(Buffer.isBuffer(cert));
  assert(options && typeof options === 'object');

  let {ttl, usage, selector, type} = options;

  if (ttl == null)
    ttl = 3600;

  if (usage == null)
    usage = 3;

  if (selector == null)
    selector = 1;

  if (type == null)
    type = 1;

  assert((ttl >>> 0) === ttl);
  assert((usage & 0xff) === usage);
  assert((selector & 0xff) === selector);
  assert((type & 0xff) === type);

  const rr = new Record();
  const rd = new TLSARecord();

  rr.name = tlsa.encodeName(name, protocol, port);
  rr.type = types.TLSA;
  rr.class = classes.INET;
  rr.ttl = ttl;
  rr.data = rd;
  rd.usage = usage;
  rd.selector = selector;
  rd.matchingType = type;
  rd.certificate = DUMMY;

  return dane.sign(rr, cert);
};

tlsa.verify = function verify(rr, cert, name, protocol, port) {
  assert(rr instanceof Record);
  assert(rr.type === types.TLSA);

  if (protocol != null) {
    if (!tlsa.verifyName(rr, name, protocol, port))
      return false;
  }

  if (!dane.verify(rr, cert))
    return false;

  return true;
};

tlsa.verifyName = function verifyName(rr, name, protocol, port) {
  assert(rr instanceof Record);
  assert(rr.type === types.TLSA);
  const encoded = tlsa.encodeName(name, protocol, port);
  return util.equal(rr.name, encoded);
};

tlsa.encodeName = function encodeName(name, protocol, port) {
  assert(util.isName(name));
  assert(name.indexOf('_') === -1);
  assert(typeof protocol === 'string');
  assert(protocol.indexOf('.') === -1);
  assert((port & 0xffff) === port);

  const encoded = util.fqdn(`_${port.toString(10)}._${protocol}.${name}`);

  assert(util.isName(encoded));

  return encoded;
};

tlsa.decodeName = function decodeName(name) {
  assert(util.isName(name));

  const labels = util.split(name);

  assert(labels.length >= 3);

  const port = util.label(name, labels, 0);
  const protocol = util.label(name, labels, 1);

  assert(port.length > 0);
  assert(protocol.length > 0);
  assert(port[0] === '_');
  assert(protocol[0] === '_');

  return {
    name: util.fqdn(util.from(name, labels, 2)),
    protocol: protocol.substring(1),
    port: util.parseU16(port.substring(1))
  };
};
