/*!
 * openpgpkey.js - OPENPGPKEY for bns
 * Copyright (c) 2018, Christopher Jeffrey (MIT License).
 * https://github.com/chjj/bns
 *
 * Resources:
 *   https://tools.ietf.org/html/rfc7929
 */

'use strict';

const assert = require('bsert');
const dane = require('./dane');
const wire = require('./wire');

const {
  types,
  classes,
  Record,
  OPENPGPKEYRecord
} = wire;

/*
 * OPENPGPKEY
 */

const openpgpkey = exports;

openpgpkey.create = function create(key, email, options = {}) {
  assert(Buffer.isBuffer(key));
  assert(options && typeof options === 'object');

  let {ttl} = options;

  if (ttl == null)
    ttl = 3600;

  assert((ttl >>> 0) === ttl);

  const rr = new Record();
  const rd = new OPENPGPKEYRecord();

  rr.name = openpgpkey.encodeEmail(email);
  rr.type = types.OPENPGPKEY;
  rr.class = classes.IN;
  rr.ttl = ttl;
  rr.data = rd;
  rd.publicKey = key;

  return rr;
};

openpgpkey.verify = function verify(rr, key) {
  assert(rr instanceof Record);
  assert(rr.type === types.OPENPGPKEY);
  assert(Buffer.isBuffer(key));

  const rd = rr.data;

  return rd.publicKey.equals(key);
};

openpgpkey.encodeEmail = function encodeEmail(email, bits) {
  return dane.encodeEmail(email, 'openpgpkey', bits);
};

openpgpkey.encodeName = function encodeName(name, local, bits) {
  return dane.encodeName(name, 'openpgpkey', local, bits);
};

openpgpkey.decodeName = function decodeName(name) {
  return dane.decodeName(name, 'openpgpkey');
};

openpgpkey.isName = function isName(name) {
  return dane.isName(name, 'openpgpkey');
};
