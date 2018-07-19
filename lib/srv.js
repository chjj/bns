/*!
 * srv.js - SRV for bns
 * Copyright (c) 2018, Christopher Jeffrey (MIT License).
 * https://github.com/chjj/bns
 *
 * Resources:
 *   https://tools.ietf.org/html/rfc2782
 */

'use strict';

const assert = require('bsert');
const util = require('./util');

/*
 * SRV
 */

const srv = exports;

srv.encodeName = function encodeName(name, protocol, service) {
  assert(util.isName(name));
  assert(name.length === 0 || name[0] !== '_');
  assert(util.isName(protocol));
  assert(protocol.length >= 1 && protocol.length <= 62);
  assert(protocol[0] !== '_');
  assert(protocol.indexOf('.') === -1);
  assert(util.isName(service));
  assert(service.length >= 1 && service.length <= 62);
  assert(service[0] !== '_');
  assert(service.indexOf('.') === -1);

  if (name === '.')
    name = '';

  const encoded = util.fqdn(`_${service}._${protocol}.${name}`);

  assert(util.isName(encoded));

  return encoded;
};

srv.decodeName = function decodeName(name) {
  assert(util.isName(name));

  const labels = util.split(name);

  assert(labels.length >= 3);

  const service = util.label(name, labels, 0);
  const protocol = util.label(name, labels, 1);

  assert(service.length >= 2);
  assert(protocol.length >= 2);
  assert(service[0] === '_');
  assert(protocol[0] === '_');

  return {
    name: util.fqdn(util.from(name, labels, 2)),
    protocol: protocol.substring(1).toLowerCase(),
    service: service.substring(1).toLowerCase()
  };
};

srv.isName = function isName(name) {
  assert(util.isName(name));

  try {
    srv.decodeName(name);
    return true;
  } catch (e) {
    return false;
  }
};
