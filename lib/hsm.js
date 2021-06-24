/*!
 * hsm.js - HSM PKCS#11 interface for bns
 * Copyright (c) 2021, Matthew Zipkin (MIT License).
 * https://github.com/chjj/bns
 */

'use strict';

const pkcs11js = require('pkcs11js');
const constants = require('./constants');

const {algs} = constants;

// Comment from pkcs11js pkcs11t.h:
// CKK_ECDSA is deprecated in v2.11, CKK_EC is preferred.
const algToKeyType = {
  [algs.RSASHA1]: pkcs11js.CKK_RSA,
  [algs.RSASHA256]: pkcs11js.CKK_RSA,
  [algs.ECDSAP256SHA256]: pkcs11js.CKK_EC,
  [algs.RSASHA512]: pkcs11js.CKK_RSA
};

exports.algToKeyType = algToKeyType;
