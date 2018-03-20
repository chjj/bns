/*!
 * smimea.js - SMIMEA for bns
 * Copyright (c) 2018, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bns
 *
 * Parts of this software are based on miekg/dns:
 *   https://github.com/miekg/dns/blob/master/smimea.go
 */

'use strict';

const assert = require('assert');
const crypto = require('./crypto');
const dane = require('./dane');
const util = require('./util');
const wire = require('./wire');
const {types, classes, Record, SMIMEARecord} = wire;
const smimea = exports;

/*
 * Constants
 */

const DUMMY = Buffer.alloc(0);

/*
 * SMIMEA
 */

smimea.create = function create(cert, name, email, options = {}) {
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
  const rd = new SMIMEARecord();

  rr.name = smimea.encodeName(name, email);
  rr.type = types.SMIMEA;
  rr.class = classes.INET;
  rr.ttl = ttl;
  rr.data = rd;
  rd.usage = usage;
  rd.selector = selector;
  rd.matchingType = type;
  rd.certificate = DUMMY;

  return dane.sign(rr, cert);
};

smimea.verify = function verify(rr, cert, name, email) {
  assert(rr instanceof Record);
  assert(rr.type === types.SMIMEA);

  if (email != null) {
    if (!smimea.verifyName(rr, name, email))
      return false;
  }

  if (!dane.verify(rr, cert))
    return false;

  return true;
};

smimea.verifyName = function verifyName(rr, name, email) {
  assert(rr instanceof Record);
  assert(rr.type === types.SMIMEA);
  const encoded = smimea.encodeName(name, email);
  return util.equal(rr.name, encoded);
};

smimea.encodeName = function encodeName(name, email) {
  assert(util.isName(name));
  assert(name.indexOf('_') === -1);
  assert(typeof email === 'string');
  assert(email.length <= 255);

  const raw = Buffer.from(email, 'ascii');
  const hash = crypto.sha256.digest(raw);
  const hex = hash.toString('hex', 0, 28);

  const encoded = util.fqdn(`_${hex}._smimecert.${name}`);

  assert(util.isName(encoded));

  return encoded;
};

smimea.decodeName = function decodeName(name) {
  assert(util.isName(name));

  const labels = util.split(name);

  assert(labels.length >= 3);

  const hex = util.label(name, labels, 0);
  const smime = util.label(name, labels, 1);

  assert(hex.length > 0);
  assert(smime.length > 0);

  assert(hex[0] === '_');
  assert(smime[0] === '_');

  if (smime.toLowerCase() !== '_smimecert')
    throw new Error('Invalid SMIMEA name.');

  if (hex.length !== 57)
    throw new Error('Invalid SMIMEA hash.');

  const hash = Buffer.from(hex.substring(1), 'hex');

  if (hash.length !== 28)
    throw new Error('Invalid SMIMEA hash.');

  return {
    name: util.fqdn(util.from(name, labels, 2)),
    hash: hash
  };
};
