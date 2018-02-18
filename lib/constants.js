/*!
 * constants.js - constants for bns
 * Copyright (c) 2018, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bns
 *
 * Parts of this software are based on miekg/dns and golang/go:
 *   https://github.com/miekg/dns/blob/master/msg.go
 *   https://github.com/miekg/dns/blob/master/types.go
 *   https://github.com/golang/go/blob/master/src/net/dnsmsg.go
 */

'use strict';

/**
 * Message Opcodes
 * @enum {Number}
 * @default
 */

const opcodes = {
  QUERY: 0,
  IQUERY: 1,
  STATUS: 2,
  NOTIFY: 4,
  UPDATE: 5,
  UNKNOWN: 15
};

/**
 * Message Opcodes By Value
 * @enum {String}
 * @default
 */

const opcodesByVal = {
  [opcodes.QUERY]: 'QUERY',
  [opcodes.IQUERY]: 'IQUERY',
  [opcodes.STATUS]: 'STATUS',
  [opcodes.NOTIFY]: 'NOTIFY',
  [opcodes.UPDATE]: 'UPDATE',
  [opcodes.UNKNOWN]: 'UNKNOWN'
};

/**
 * Message Flags
 * @enum {Number}
 * @default
 */

const flags = {
  QR: 1 << 15, // query/response (response=1)
  AA: 1 << 10, // authoritative
  TC: 1 << 9,  // truncated
  RD: 1 << 8,  // recursion desired
  RA: 1 << 7,  // recursion available
  Z: 1 << 6,  // Z
  AD: 1 << 5,  // authenticated data
  CD: 1 << 4  // checking disabled
};

/**
 * Message Flags By Value
 * @enum {String}
 * @default
 */

const flagsByVal = {
  [flags.QR]: 'QR',
  [flags.AA]: 'AA',
  [flags.TC]: 'TC',
  [flags.RD]: 'RD',
  [flags.RA]: 'RA',
  [flags.Z]: 'Z',
  [flags.AD]: 'AD',
  [flags.CD]: 'CD'
};

/**
 * Response Codes (rcodes)
 * @see https://www.iana.org/assignments/dns-parameters/dns-parameters.xhtml
 * @enum {Number}
 * @default
 */

const codes = {
  NOERROR: 0, // No Error
  SUCCESS: 0, // No Error
  FORMATERROR: 1, // Format Error
  SERVERFAILURE: 2, // Server Failure
  NXDOMAIN: 3, // Non-Existent Domain
  NOTIMPLEMENTED: 4, // Not Implemented
  REFUSED: 5, // Query Refused
  YXDOMAIN: 6, // Name Exists when it should not
  YXRRSET: 7, // RR Set Exists when it should not
  NXRRSET: 8, // RR Set that should exist does not
  NOTAUTH: 9, // Server Not Authoritative for zone
  NOTZONE: 10, // Name not contained in zone
  UNKNOWN: 15,
  BADSIG: 16, // TSIG Signature Failure
  BADVERS: 16, // Bad OPT Version
  BADKEY: 17, // Key not recognized
  BADTIME: 18, // Signature out of time window
  BADMODE: 19, // Bad TKEY Mode
  BADNAME: 20, // Duplicate key name
  BADALG: 21, // Algorithm not supported
  BADTRUNC: 22, // Bad Truncation
  BADCOOKIE: 23 // Bad/missing Server Cookie
};

/**
 * Response Codes By Value
 * @enum {String}
 * @default
 */

const codesByVal = {
  [codes.NOERROR]: 'NOERROR',
  [codes.FORMATERROR]: 'FORMATERROR',
  [codes.SERVERFAILURE]: 'SERVERFAILURE',
  [codes.NXDOMAIN]: 'NXDOMAIN',
  [codes.NOTIMPLEMENTED]: 'NOTIMPLEMENTED',
  [codes.REFUSED]: 'REFUSED',
  [codes.YXDOMAIN]: 'YXDOMAIN',
  [codes.YXRRSET]: 'YXRRSET',
  [codes.NXRRSET]: 'NXRRSET',
  [codes.NOTAUTH]: 'NOTAUTH',
  [codes.NOTZONE]: 'NOTZONE',
  [codes.UNKNOWN]: 'UNKNOWN',
  [codes.BADSIG]: 'BADSIG',
  [codes.BADVERS]: 'BADVERS',
  [codes.BADKEY]: 'BADKEY',
  [codes.BADTIME]: 'BADTIME',
  [codes.BADMODE]: 'BADMODE',
  [codes.BADNAME]: 'BADNAME',
  [codes.BADALG]: 'BADALG',
  [codes.BADTRUNC]: 'BADTRUNC',
  [codes.BADCOOKIE]: 'BADCOOKIE'
};

/**
 * Record Types (rrtypes)
 * @enum {Number}
 * @default
 */

const types = {
  UNKNOWN: 0,
  A: 1,
  NS: 2,
  MD: 3, // obsolete
  MF: 4, // obsolete
  CNAME: 5,
  SOA: 6,
  MB: 7, // experimental
  MG: 8, // experimental
  MR: 9, // experimental
  NULL: 10, // obsolete
  WKS: 11, // deprecated
  PTR: 12,
  HINFO: 13, // not-in-use
  MINFO: 14, // experimental
  MX: 15,
  TXT: 16,
  RP: 17,
  AFSDB: 18,
  X25: 19, // not-in-use
  ISDN: 20, // not-in-use
  RT: 21, // not-in-use
  NSAP: 22, // not-in-use
  NSAPPTR: 23, // not-in-use
  SIG: 24, // obsolete
  KEY: 25, // obsolete
  PX: 26, // not-in-use
  GPOS: 27, // deprecated
  AAAA: 28,
  LOC: 29,
  NXT: 30, // obsolete
  EID: 31, // not-in-use
  NIMLOC: 32, // not-in-use (used to be NB)
  SRV: 33, // used to be NBSTAT
  ATMA: 34, // not-in-use
  NAPTR: 35,
  KX: 36,
  CERT: 37,
  A6: 38, // historic
  DNAME: 39,
  SINK: 40, // unimpl (joke?)
  OPT: 41, // impl (pseudo-record, edns)
  APL: 42, // not-in-use
  DS: 43,
  SSHFP: 44,
  IPSECKEY: 45,
  RRSIG: 46,
  NSEC: 47,
  DNSKEY: 48,
  DHCID: 49,
  NSEC3: 50,
  NSEC3PARAM: 51,
  TLSA: 52,
  SMIMEA: 53,
  HIP: 55,
  NINFO: 56, // proposed
  RKEY: 57, // proposed
  TALINK: 58, // proposed
  CDS: 59,
  CDNSKEY: 60,
  OPENPGPKEY: 61,
  CSYNC: 62,
  SPF: 99, // obsolete
  UINFO: 100, // obsolete
  UID: 101, // obsolete
  GID: 102, // obsolete
  UNSPEC: 103, // obsolete
  NID: 104,
  L32: 105,
  L64: 106,
  LP: 107,
  EUI48: 108,
  EUI64: 109,
  URI: 256,
  CAA: 257,
  AVC: 258, // proposed
  TKEY: 249,
  TSIG: 250,
  IXFR: 251, // unimpl (pseudo-record)
  AXFR: 252, // unimpl (pseudo-record)
  MAILB: 253, // experimental, unimpl (qtype)
  MAILA: 254, // obsolete, unimpl (qtype)
  ANY: 255, // impl (qtype)
  TA: 32768,
  DLV: 32769,
  NAMEPROOF: 259,
  RESERVED: 65535 // unimpl
};

/**
 * Record Types by value
 * @enum {String}
 * @default
 */

const typesByVal = {
  [types.UNKNOWN]: 'UNKNOWN',
  [types.A]: 'A',
  [types.NS]: 'NS',
  [types.MD]: 'MD',
  [types.MF]: 'MF',
  [types.CNAME]: 'CNAME',
  [types.SOA]: 'SOA',
  [types.MB]: 'MB',
  [types.MG]: 'MG',
  [types.MR]: 'MR',
  [types.NULL]: 'NULL',
  [types.WKS]: 'WKS',
  [types.PTR]: 'PTR',
  [types.HINFO]: 'HINFO',
  [types.MINFO]: 'MINFO',
  [types.MX]: 'MX',
  [types.TXT]: 'TXT',
  [types.RP]: 'RP',
  [types.AFSDB]: 'AFSDB',
  [types.X25]: 'X25',
  [types.ISDN]: 'ISDN',
  [types.RT]: 'RT',
  [types.NSAP]: 'NSAP',
  [types.NSAPPTR]: 'NSAPPTR',
  [types.SIG]: 'SIG',
  [types.KEY]: 'KEY',
  [types.PX]: 'PX',
  [types.GPOS]: 'GPOS',
  [types.AAAA]: 'AAAA',
  [types.LOC]: 'LOC',
  [types.NXT]: 'NXT',
  [types.EID]: 'EID',
  [types.NIMLOC]: 'NIMLOC',
  [types.SRV]: 'SRV',
  [types.ATMA]: 'ATMA',
  [types.NAPTR]: 'NAPTR',
  [types.KX]: 'KX',
  [types.CERT]: 'CERT',
  [types.A6]: 'A6',
  [types.DNAME]: 'DNAME',
  [types.SINK]: 'SINK',
  [types.OPT]: 'OPT',
  [types.APL]: 'APL',
  [types.DS]: 'DS',
  [types.SSHFP]: 'SSHFP',
  [types.IPSECKEY]: 'IPSECKEY',
  [types.RRSIG]: 'RRSIG',
  [types.NSEC]: 'NSEC',
  [types.DNSKEY]: 'DNSKEY',
  [types.DHCID]: 'DHCID',
  [types.NSEC3]: 'NSEC3',
  [types.NSEC3PARAM]: 'NSEC3PARAM',
  [types.TLSA]: 'TLSA',
  [types.SMIMEA]: 'SMIMEA',
  [types.HIP]: 'HIP',
  [types.NINFO]: 'NINFO',
  [types.RKEY]: 'RKEY',
  [types.TALINK]: 'TALINK',
  [types.CDS]: 'CDS',
  [types.CDNSKEY]: 'CDNSKEY',
  [types.OPENPGPKEY]: 'OPENPGPKEY',
  [types.CSYNC]: 'CSYNC',
  [types.SPF]: 'SPF',
  [types.UINFO]: 'UINFO',
  [types.UID]: 'UID',
  [types.GID]: 'GID',
  [types.UNSPEC]: 'UNSPEC',
  [types.NID]: 'NID',
  [types.L32]: 'L32',
  [types.L64]: 'L64',
  [types.LP]: 'LP',
  [types.EUI48]: 'EUI48',
  [types.EUI64]: 'EUI64',
  [types.URI]: 'URI',
  [types.CAA]: 'CAA',
  [types.AVC]: 'AVC',
  [types.TKEY]: 'TKEY',
  [types.TSIG]: 'TSIG',
  [types.IXFR]: 'IXFR',
  [types.AXFR]: 'AXFR',
  [types.MAILB]: 'MAILB',
  [types.MAILA]: 'MAILA',
  [types.ANY]: 'ANY',
  [types.TA]: 'TA',
  [types.DLV]: 'DLV',
  [types.NAMEPROOF]: 'NAMEPROOF',
  [types.RESERVED]: 'RESERVED'
};

/**
 * Question and Record Classes (qclass/rclass)
 * @enum {Number}
 * @default
 */

const classes = {
  UNKNOWN: 0,
  INET: 1,
  CSNET: 2,
  CHAOS: 3,
  HESIOD: 4,
  NONE: 254,
  ANY: 255
};

/**
 * Question and Record Classes By Value
 * @enum {String}
 * @default
 */

const classesByVal = {
  [classes.UNKNOWN]: 'UNKNOWN',
  [classes.INET]: 'INET',
  [classes.CSNET]: 'CSNET',
  [classes.CHAOS]: 'CHAOS',
  [classes.HESIOD]: 'HESIOD',
  [classes.NONE]: 'NONE',
  [classes.ANY]: 'ANY'
};

/**
 * Short Question and Record Classes (qclass/rclass)
 * @enum {Number}
 * @default
 */

const short = {
  UN: classes.UNKNOWN,
  IN: classes.INET,
  CS: classes.CSNET,
  CH: classes.CHAOS,
  HE: classes.HESIOD,
  NO: classes.NONE,
  AN: classes.ANY
};

/**
 * Short Question and Record Classes By Value
 * @enum {String}
 * @default
 */

const shortByVal = {
  [short.UN]: 'UN',
  [short.IN]: 'IN',
  [short.CS]: 'CS',
  [short.CH]: 'CH',
  [short.HE]: 'HE',
  [short.NO]: 'NO',
  [short.AN]: 'AN'
};

/**
 * EDNS0 Flags
 * @enum {Number}
 * @default
 */

const eflags = {
  DO: 1 << 15 // DNSSEC OK
};

/**
 * EDNS0 Flags by value
 * @enum {Number}
 * @default
 */

const eflagsByVal = {
  [eflags.DO]: 'DO'
};

/**
 * EDNS0 Option Codes
 * @enum {Number}
 * @default
 */

const options = {
  UNKNOWN: 0, // None
  LLQ: 1, // Long Lived Queries
  UL: 2, // Update Lease Draft
  NSID: 3, // Nameserver Identifier
  DAU: 5, // DNSSEC Algorithm Understood
  DHU: 6, // DS Hash Understood
  N3U: 7, // NSEC3 Hash Understood
  SUBNET: 8, // Client Subnet
  EXPIRE: 9, // Expire
  COOKIE: 10, // Cookie
  TCPKEEPALIVE: 11, // TCP Keep-Alive
  PADDING: 12, // Padding
  TRIEROOT: 13,
  LOCAL: 65001, // Beginning of range reserved for local/experimental use
  LOCALSTART: 65001, // Beginning of range reserved for local/experimental use
  LOCALEND: 65534 // End of range reserved for local/experimental use
};

/**
 * EDNS0 Option Codes By Value
 * @enum {Number}
 * @default
 */

const optionsByVal = {
  [options.UNKNOWN]: 'UNKNOWN',
  [options.LLQ]: 'LLQ',
  [options.UL]: 'UL',
  [options.NSID]: 'NSID',
  [options.DAU]: 'DAU',
  [options.DHU]: 'DHU',
  [options.N3U]: 'N3U',
  [options.SUBNET]: 'SUBNET',
  [options.EXPIRE]: 'EXPIRE',
  [options.COOKIE]: 'COOKIE',
  [options.TCPKEEPALIVE]: 'TCPKEEPALIVE',
  [options.PADDING]: 'PADDING',
  [options.TRIEROOT]: 'TRIEROOT',
  [options.LOCALSTART]: 'LOCALSTART',
  [options.LOCALEND]: 'LOCALEND'
};

/**
 * For RFC1982 (Serial Arithmetic) calculations in 32 bits.
 * @const {Number}
 * @default
 */

const YEAR68 = (1 << 31) >>> 0;

/*
 * Expose
 */

exports.opcodes = opcodes;
exports.opcodesByVal = opcodesByVal;
exports.flags = flags;
exports.flagsByVal = flagsByVal;
exports.codes = codes;
exports.codesByVal = codesByVal;
exports.types = types;
exports.typesByVal = typesByVal;
exports.classes = classes;
exports.classesByVal = classesByVal;
exports.short = short;
exports.shortByVal = shortByVal;
exports.eflags = eflags;
exports.eflagsByVal = eflagsByVal;
exports.options = options;
exports.optionsByVal = optionsByVal;
exports.YEAR68 = YEAR68;
