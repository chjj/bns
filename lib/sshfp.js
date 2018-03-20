/*!
 * sshfp.js - SSHFP for bns
 * Copyright (c) 2018, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bns
 */

'use strict';

const assert = require('assert');
const crypto = require('./crypto');
const util = require('./util');
const wire = require('./wire');
const {types, classes, Record, SSHFPRecord} = wire;
const sshfp = exports;

/*
 * Constants
 */

const algs = {
  RSA: 1,
  DSS: 2
};

const hashes = {
  SHA1: 1
};

const DUMMY = Buffer.alloc(0);

/*
 * SSHFP
 */

sshfp.create = function create(key, name, alg, digest) {
  assert(Buffer.isBuffer(key));

  assert((alg & 0xff) === alg);
  assert((digest & 0xff) === digest);

  assert(alg === algs.RSA || alg === algs.DSS);
  assert(digest === algs.SHA1);

  const rr = new Record();
  const rd = new SSHFPRecord();

  rr.name = util.fqdn(name);
  rr.type = types.SSHFP;
  rr.class = classes.INET;
  rr.ttl = 0;
  rr.data = rd;
  rd.algorithm = alg;
  rd.digestType = digest;
  rd.fingerprint = DUMMY;

  return sshfp.sign(rr, key);
};

sshfp.sign = function sign(rr, key) {
  assert(rr instanceof Record);
  assert(rr.type === types.SSHFP);

  const rd = rr.data;
  const type = rd.digestType;

  switch (type) {
    case hashes.SHA1:
      rd.fingerprint = crypto.sha1.digest(key);
      break;
    default:
      throw new Error('Unknown digest type.');
  }

  return rr;
};

sshfp.verify = function verify(rr, key) {
  assert(rr instanceof Record);
  assert(rr.type === types.SSHFP);

  const rd = rr.data;
  const type = rd.digestType;

  let hash;

  switch (type) {
    case hashes.SHA1:
      hash = crypto.sha1.digest(key);
      break;
    default:
      return false;
  }

  return rd.fingerprint.equals(hash);
};

/*
 * Expose
 */

sshfp.algs = algs;
sshfp.hashes = hashes;
