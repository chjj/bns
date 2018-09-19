/*!
 * smimea.js - SMIMEA for bns
 * Copyright (c) 2018, Christopher Jeffrey (MIT License).
 * https://github.com/chjj/bns
 *
 * Parts of this software are based on miekg/dns:
 *   https://github.com/miekg/dns/blob/master/smimea.go
 *
 * Resources:
 *   https://tools.ietf.org/html/rfc6698
 */

'use strict';

const assert = require('bsert');
const dane = require('./dane');
const wire = require('./wire');

const {
  usages,
  selectors,
  matchingTypes
} = dane;

const {
  types,
  classes,
  Record,
  SMIMEARecord
} = wire;

/*
 * SMIMEA
 */

const smimea = exports;

smimea.create = function create(cert, email, options = {}) {
  assert(Buffer.isBuffer(cert));
  assert(options && typeof options === 'object');

  let {ttl, usage, selector, matchingType} = options;

  if (ttl == null)
    ttl = 3600;

  if (usage == null)
    usage = usages.DIC;

  if (selector == null)
    selector = selectors.SPKI;

  if (matchingType == null)
    matchingType = matchingTypes.SHA256;

  assert((ttl >>> 0) === ttl);
  assert((usage & 0xff) === usage);
  assert((selector & 0xff) === selector);
  assert((matchingType & 0xff) === matchingType);

  const rr = new Record();
  const rd = new SMIMEARecord();

  rr.name = smimea.encodeEmail(email);
  rr.type = types.SMIMEA;
  rr.class = classes.IN;
  rr.ttl = ttl;
  rr.data = rd;
  rd.usage = usage;
  rd.selector = selector;
  rd.matchingType = matchingType;

  const hash = dane.sign(cert, selector, matchingType);

  if (!hash)
    throw new Error('Unknown selector or matching type.');

  rd.certificate = hash;

  return rr;
};

smimea.verify = function verify(rr, cert) {
  assert(rr instanceof Record);
  assert(rr.type === types.SMIMEA);

  const rd = rr.data;

  return dane.verify(cert, rd.selector, rd.matchingType, rd.certificate);
};

smimea.encodeEmail = function encodeEmail(email, bits) {
  return dane.encodeEmail(email, 'smimecert', bits);
};

smimea.encodeName = function encodeName(name, local, bits) {
  return dane.encodeName(name, 'smimecert', local, bits);
};

smimea.decodeName = function decodeName(name) {
  return dane.decodeName(name, 'smimecert');
};

smimea.isName = function isName(name) {
  return dane.isName(name, 'smimecert');
};

/*
 * Expose
 */

smimea.usages = usages;
smimea.selectors = selectors;
smimea.matchingTypes = matchingTypes;
