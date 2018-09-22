/*!
 * sshfp.js - SSHFP for bns
 * Copyright (c) 2018, Christopher Jeffrey (MIT License).
 * https://github.com/chjj/bns
 */

'use strict';

const assert = require('bsert');
const constants = require('./constants');
const crypto = require('./internal/crypto');
const util = require('./util');
const wire = require('./wire');

const {
  types,
  classes,
  sshAlgs,
  sshAlgsByVal,
  sshHashes,
  sshHashesByVal
} = constants;

const {
  Record,
  SSHFPRecord
} = wire;

/*
 * SSHFP
 */

const sshfp = exports;

sshfp.hash = function hash(key, digestType) {
  assert(Buffer.isBuffer(key));
  assert((digestType & 0xff) === digestType);

  switch (digestType) {
    case sshHashes.SHA1:
      return crypto.sha1.digest(key);
    case sshHashes.SHA256:
      return crypto.sha256.digest(key);
  }

  return null;
};

sshfp.validate = function validate(key, digestType, fingerprint) {
  assert(Buffer.isBuffer(fingerprint));

  const hash = sshfp.hash(key, digestType);

  if (!hash)
    return false;

  return hash.equals(fingerprint);
};

sshfp.create = function create(key, name, alg, digest) {
  assert(Buffer.isBuffer(key));
  assert(typeof name === 'string');
  assert((alg & 0xff) === alg);
  assert((digest & 0xff) === digest);

  const rr = new Record();
  const rd = new SSHFPRecord();

  rr.name = util.fqdn(name);
  rr.type = types.SSHFP;
  rr.class = classes.IN;
  rr.ttl = 172800;
  rr.data = rd;
  rd.algorithm = alg;
  rd.digestType = digest;

  return sshfp.sign(rr, key);
};

sshfp.sign = function sign(rr, key) {
  assert(rr instanceof Record);
  assert(rr.type === types.SSHFP);

  const rd = rr.data;
  const hash = sshfp.hash(key, rd.digestType);

  if (!hash)
    throw new Error('Unknown digest type.');

  rd.fingerprint = hash;

  return rr;
};

sshfp.verify = function verify(rr, key) {
  assert(rr instanceof Record);
  assert(rr.type === types.SSHFP);

  const rd = rr.data;

  return sshfp.validate(key, rd.digestType, rd.fingerprint);
};

/*
 * Expose
 */

sshfp.algs = sshAlgs;
sshfp.algsByVal = sshAlgsByVal;
sshfp.hashes = sshHashes;
sshfp.hashesByVal = sshHashesByVal;
