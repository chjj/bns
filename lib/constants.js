/*!
 * constants.js - constants for bns
 * Copyright (c) 2018, Christopher Jeffrey (MIT License).
 * https://github.com/chjj/bns
 *
 * Parts of this software are based on miekg/dns and golang/go:
 *   https://github.com/miekg/dns/blob/master/msg.go
 *   https://github.com/miekg/dns/blob/master/types.go
 *   https://github.com/golang/go/blob/master/src/net/dnsmsg.go
 *
 * Resources:
 *   https://www.iana.org/assignments/dns-parameters/dns-parameters.xhtml
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
  // 3 is unassigned
  NOTIFY: 4,
  UPDATE: 5
  // 6-15 are unassigned
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
  [opcodes.UPDATE]: 'UPDATE'
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
  FORMERR: 1, // Format Error
  SERVFAIL: 2, // Server Failure
  NXDOMAIN: 3, // Non-Existent Domain
  NOTIMP: 4, // Not Implemented
  REFUSED: 5, // Query Refused
  YXDOMAIN: 6, // Name Exists when it should not
  YXRRSET: 7, // RR Set Exists when it should not
  NXRRSET: 8, // RR Set that should exist does not
  NOTAUTH: 9, // Server Not Authoritative for zone
  NOTZONE: 10, // Name not contained in zone

  // 11-15 are unassigned

  // EDNS
  BADSIG: 16, // TSIG Signature Failure
  BADVERS: 16, // Bad OPT Version
  BADKEY: 17, // Key not recognized
  BADTIME: 18, // Signature out of time window
  BADMODE: 19, // Bad TKEY Mode
  BADNAME: 20, // Duplicate key name
  BADALG: 21, // Algorithm not supported
  BADTRUNC: 22, // Bad Truncation
  BADCOOKIE: 23, // Bad/missing Server Cookie

  // 24-3840 are unassigned

  // 3841-4095 reserved for private use

  // 4096-65534 unassigned

  RESERVED: 65535
};

/**
 * Response Codes By Value
 * @enum {String}
 * @default
 */

const codesByVal = {
  [codes.NOERROR]: 'NOERROR',
  [codes.FORMERR]: 'FORMERR',
  [codes.SERVFAIL]: 'SERVFAIL',
  [codes.NXDOMAIN]: 'NXDOMAIN',
  [codes.NOTIMP]: 'NOTIMP',
  [codes.REFUSED]: 'REFUSED',
  [codes.YXDOMAIN]: 'YXDOMAIN',
  [codes.YXRRSET]: 'YXRRSET',
  [codes.NXRRSET]: 'NXRRSET',
  [codes.NOTAUTH]: 'NOTAUTH',
  [codes.NOTZONE]: 'NOTZONE',
  // edns
  [codes.BADVERS]: 'BADVERS',
  [codes.BADKEY]: 'BADKEY',
  [codes.BADTIME]: 'BADTIME',
  [codes.BADMODE]: 'BADMODE',
  [codes.BADNAME]: 'BADNAME',
  [codes.BADALG]: 'BADALG',
  [codes.BADTRUNC]: 'BADTRUNC',
  [codes.BADCOOKIE]: 'BADCOOKIE',
  [codes.RESERVED]: 'RESERVED'
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

  // 54 is unassigned

  HIP: 55,
  NINFO: 56, // proposed
  RKEY: 57, // proposed
  TALINK: 58, // proposed
  CDS: 59,
  CDNSKEY: 60,
  OPENPGPKEY: 61,
  CSYNC: 62,

  // 63-98 are unassigned

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

  // 110-248 are unassigned

  TKEY: 249,
  TSIG: 250,
  IXFR: 251, // unimpl (pseudo-record)
  AXFR: 252, // unimpl (pseudo-record)
  MAILB: 253, // experimental, unimpl (qtype)
  MAILA: 254, // obsolete, unimpl (qtype)

  ANY: 255, // impl (qtype)
  URI: 256,
  CAA: 257,
  AVC: 258, // proposed
  DOA: 259, // proposed
  // OX: 260, // proposed successor to DOA?

  // 260-32767 are unassigned

  TA: 32768,
  DLV: 32769,

  // 32770-65279 are unassigned
  // 65280-65534 reserved for private use

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
  [types.TKEY]: 'TKEY',
  [types.TSIG]: 'TSIG',
  [types.IXFR]: 'IXFR',
  [types.AXFR]: 'AXFR',
  [types.MAILB]: 'MAILB',
  [types.MAILA]: 'MAILA',
  [types.URI]: 'URI',
  [types.CAA]: 'CAA',
  [types.AVC]: 'AVC',
  [types.DOA]: 'DOA',
  // [types.OX]: 'OX',
  [types.ANY]: 'ANY',
  [types.TA]: 'TA',
  [types.DLV]: 'DLV',
  [types.RESERVED]: 'RESERVED'
};

/**
 * Question and Record Classes (qclass/rclass)
 * @enum {Number}
 * @default
 */

const classes = {
  RESERVED0: 0,
  IN: 1, // INET

  // 2 is unassigned (used to be CSNET/CS)

  CH: 3, // CHAOS
  HS: 4, // HESIOD

  // 5-253 are unassigned

  NONE: 254,
  ANY: 255,

  // 256-65279 are unassigned
  // 65280-65534 are reserved for private use

  RESERVED65535: 65535
};

/**
 * Question and Record Classes By Value
 * @enum {String}
 * @default
 */

const classesByVal = {
  [classes.RESERVED0]: 'RESERVED0',
  [classes.IN]: 'IN',
  [classes.CH]: 'CH',
  [classes.HS]: 'HS',
  [classes.NONE]: 'NONE',
  [classes.ANY]: 'ANY',
  [classes.RESERVED65535]: 'RESERVED65535'
};

/**
 * EDNS0 Flags
 * @enum {Number}
 * @default
 */

const eflags = {
  DO: 1 << 15 // DNSSEC OK
  // 1-15 are reserved
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
  RESERVED: 0, // None
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
  CHAIN: 13, // Chain
  KEYTAG: 14, // EDNS Key Tag

  // 15-26945 are unassigned

  // DEVICEID: 26946,

  // 26947-65000 are unassigned

  LOCAL: 65001, // Beginning of range reserved for local/experimental use
  LOCALSTART: 65001, // Beginning of range reserved for local/experimental use

  // 65001-65534 are reserved for experimental use

  LOCALEND: 65534 // End of range reserved for local/experimental use

  // 65535 is reserved
};

/**
 * EDNS0 Option Codes By Value
 * @enum {Number}
 * @default
 */

const optionsByVal = {
  [options.RESERVED]: 'RESERVED',
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
  [options.CHAIN]: 'CHAIN',
  [options.KEYTAG]: 'KEYTAG',
  // [options.DEVICEID]: 'DEVICEID',
  [options.LOCAL]: 'LOCAL'
};

/**
 * DNSKEY flag values.
 * See RFC4034, Section 2.1.1
 * Note that their endianness is backwards,
 * Subtract each bit value from 15 to convert.
 * @see https://www.ietf.org/rfc/rfc4034.txt
 * @enum {Number}
 * @default
 */

const keyFlags = {
  KSK: 1 << 0,
  SEP: 1 << 0,
  // 1-6 reserved
  REVOKE: 1 << 7,
  ZONE: 1 << 8
  // 9-15 reserved
};

/**
 * DNSSEC encryption algorithm codes.
 * @enum {Number}
 * @default
 */

const algs = {
  // _: 0,
  RSAMD5: 1,
  DH: 2,
  DSA: 3,
  ECC: 4,
  RSASHA1: 5,
  DSANSEC3SHA1: 6,
  RSASHA1NSEC3SHA1: 7,
  RSASHA256: 8,
  // _: 9,
  RSASHA512: 10,
  // _: 11,
  ECCGOST: 12,
  ECDSAP256SHA256: 13,
  ECDSAP384SHA384: 14,
  ED25519: 15,
  ED448: 16,
  INDIRECT: 252,
  PRIVATEDNS: 253, // Private (experimental keys)
  PRIVATEOID: 254
};

/**
 * DNSSEC algorithm codes by value.
 * @const {Object}
 */

const algsByVal = {
  [algs.RSAMD5]: 'RSAMD5',
  [algs.DH]: 'DH',
  [algs.DSA]: 'DSA',
  [algs.ECC]: 'ECC',
  [algs.RSASHA1]: 'RSASHA1',
  [algs.DSANSEC3SHA1]: 'DSANSEC3SHA1',
  [algs.RSASHA1NSEC3SHA1]: 'RSASHA1NSEC3SHA1',
  [algs.RSASHA256]: 'RSASHA256',
  [algs.RSASHA512]: 'RSASHA512',
  [algs.ECCGOST]: 'ECCGOST',
  [algs.ECDSAP256SHA256]: 'ECDSAP256SHA256',
  [algs.ECDSAP384SHA384]: 'ECDSAP384SHA384',
  [algs.ED25519]: 'ED25519',
  [algs.ED448]: 'ED448',
  [algs.INDIRECT]: 'INDIRECT',
  [algs.PRIVATEDNS]: 'PRIVATEDNS',
  [algs.PRIVATEOID]: 'PRIVATEOID'
};

/**
 * DNSSEC hashing algorithm codes.
 * @enum {Number}
 * @default
 */

const hashes = {
  // _: 0,
  SHA1: 1, // RFC 4034
  SHA256: 2, // RFC 4509
  GOST94: 3, // RFC 5933
  SHA384: 4, // Experimental
  SHA512: 5 // Experimental
};

/**
 * DNSSEC hashing algorithm codes by value.
 * @const {Object}
 */

const hashesByVal = {
  [hashes.SHA1]: 'SHA1',
  [hashes.SHA256]: 'SHA256',
  [hashes.GOST94]: 'GOST94',
  [hashes.SHA384]: 'SHA384',
  [hashes.SHA512]: 'SHA512'
};

/**
 * Corresponding hashes for algorithms.
 * @const {Object}
 */

const algHashes = {
  [algs.RSAMD5]: null, // Deprecated in RFC 6725 (introduced in rfc2537)
  [algs.DSA]: hashes.SHA1,
  [algs.RSASHA1]: hashes.SHA1,
  [algs.DSANSEC3SHA1]: hashes.SHA1,
  [algs.RSASHA1NSEC3SHA1]: hashes.SHA1,
  [algs.RSASHA256]: hashes.SHA256,
  [algs.ECDSAP256SHA256]: hashes.SHA256,
  [algs.ECDSAP384SHA384]: hashes.SHA384,
  [algs.RSASHA512]: hashes.SHA512,
  [algs.ED25519]: null,
  [algs.ED448]: null
};

/**
 * NSEC3 hashes.
 * @enum {Number}
 * @default
 */

const nsecHashes = {
  SHA1: 1
};

/**
 * NSEC3 hashes by value.
 * @const {Object}
 */

const nsecHashesByVal = {
  [nsecHashes.SHA1]: 'SHA1'
};

/**
 * CERT types (rfc4398).
 * @enum {Number}
 * @default
 */

const certTypes = {
  // 0 reserved
  PKIX: 1,
  SPKI: 2,
  PGP: 3,
  IPKIX: 4,
  ISPKI: 5,
  IPGP: 6,
  ACPKIX: 7,
  IACPKIX: 8,
  // 9-252 unassigned
  URI: 253,
  OID: 254
  // 255 reserved
  // 256-65279 unassigned
  // 65280-65534 experimental
  // 65535 reserved
};

/**
 * CERT types by value.
 * @const {Object}
 */

const certTypesByVal = {
  [certTypes.PKIX]: 'PKIX',
  [certTypes.SPKI]: 'SPKI',
  [certTypes.PGP]: 'PGP',
  [certTypes.IPKIX]: 'IPKIX',
  [certTypes.ISPKI]: 'ISPKI',
  [certTypes.IPGP]: 'IPGP',
  [certTypes.ACPKIX]: 'ACPKIX',
  [certTypes.IACPKIX]: 'IACPKIX',
  [certTypes.URI]: 'URI',
  [certTypes.OID]: 'OID'
};

/**
 * DANE usages.
 * @enum {Number}
 * @default
 */

const usages = {
  CAC: 0, // CA constraint
  SCC: 1, // Service certificate constraint
  TAA: 2, // Trust anchor assertion
  DIC: 3, // Domain-issued certificate
  // 4-254 are unassigned
  PRIVATE: 255 // Private Use
};

/**
 * DANE usages by value.
 * @const {Object}
 */

const usagesByVal = {
  [usages.CAC]: 'CAC',
  [usages.SCC]: 'SCC',
  [usages.TAA]: 'TAA',
  [usages.DIC]: 'DIC',
  [usages.PRIVATE]: 'PRIVATE'
};

/**
 * DANE selectors.
 * @enum {Number}
 * @default
 */

const selectors = {
  FULL: 0, // Full Certificate
  SPKI: 1, // SubjectPublicKeyInfo
  // 2-254 are unassigned
  PRIVATE: 255 // Private Use
};

/**
 * DANE selectors by value.
 * @const {Object}
 */

const selectorsByVal = {
  [selectors.FULL]: 'FULL',
  [selectors.SPKI]: 'SPKI',
  [selectors.PRIVATE]: 'PRIVATE'
};

/**
 * DANE matching types.
 * @enum {Number}
 * @default
 */

const matchingTypes = {
  NONE: 0, // No hash used
  SHA256: 1,
  SHA512: 2,
  // 3-254 are unassigned
  PRIVATE: 255 // Private Use
};

/**
 * DANE matching types by value.
 * @const {Object}
 */

const matchingTypesByVal = {
  [matchingTypes.NONE]: 'NONE',
  [matchingTypes.SHA256]: 'SHA256',
  [matchingTypes.SHA512]: 'SHA512',
  [matchingTypes.PRIVATE]: 'PRIVATE'
};

/**
 * SSHFP algorithms.
 * @enum {Number}
 * @default
 */

const sshAlgs = {
  RSA: 1,
  DSA: 2,
  ECDSA: 3,
  ED25519: 4
};

/**
 * SSHFP algorithms by value.
 * @const {Object}
 * @default
 */

const sshAlgsByVal = {
  [sshAlgs.RSA]: 'RSA',
  [sshAlgs.DSA]: 'DSA',
  [sshAlgs.ECDSA]: 'ECDSA',
  [sshAlgs.ED25519]: 'ED25519'
};

/**
 * SSHFP hashes.
 * @enum {Number}
 * @default
 */

const sshHashes = {
  SHA1: 1,
  SHA256: 2
};

/**
 * SSHFP hashes by value.
 * @const {Object}
 * @default
 */

const sshHashesByVal = {
  [sshHashes.SHA1]: 'SHA1',
  [sshHashes.SHA256]: 'SHA256'
};

/**
 * TSIG hash algorithms.
 * @const {Object}
 * @default
 */

const tsigAlgs = {
  MD5: 'hmac-md5.sig-alg.reg.int.',
  SHA1: 'hmac-sha1.',
  SHA256: 'hmac-sha256.',
  SHA512: 'hmac-sha512.'
};

/**
 * TSIG hash algorithms by value.
 * @const {Object}
 * @default
 */

const tsigAlgsByVal = {
  [tsigAlgs.MD5]: 'MD5',
  [tsigAlgs.SHA1]: 'SHA1',
  [tsigAlgs.SHA256]: 'SHA256',
  [tsigAlgs.SHA512]: 'SHA512'
};

/**
 * TKEY modes.
 * @enum {Number}
 * @default
 */

const tkeyModes = {
  RESERVED: 0, // reserved
  SERVER: 1, // server assignment
  DH: 2, // Diffie-Hellman exchange
  GSS: 3, // GSS-API negotiation
  RESOLVER: 4, // resolver assignment
  DELETE: 5 // key deletion
  // 6-65534 unassigned
  // 65535 reserved
};

/**
 * TKEY modes by value.
 * @const {Object}
 * @default
 */

const tkeyModesByVal = {
  [tkeyModes.RESERVED]: 'RESERVED',
  [tkeyModes.SERVER]: 'SERVER',
  [tkeyModes.DH]: 'DH',
  [tkeyModes.GSS]: 'GSS',
  [tkeyModes.RESOLVER]: 'RESOLVER',
  [tkeyModes.DELETE]: 'DELETE'
};

/**
 * For RFC1982 (Serial Arithmetic) calculations in 32 bits.
 * @const {Number}
 * @default
 */

const YEAR68 = (1 << 31) >>> 0;

/**
 * Equator.
 * @const {Number}
 * @default
 */

const LOC_EQUATOR = (1 << 31) >>> 0; // RFC 1876, Section 2.

/**
 * Prime meridian.
 * @const {Number}
 * @default
 */

const LOC_PRIMEMERIDIAN = (1 << 31) >>> 0; // RFC 1876, Section 2.

/**
 * Location hours.
 * @const {Number}
 * @default
 */

const LOC_HOURS = 60 * 1000;

/**
 * Location degrees.
 * @const {Number}
 * @default
 */

const LOC_DEGREES = 60 * LOC_HOURS;

/**
 * Altitude base.
 * @const {Number}
 * @default
 */

const LOC_ALTITUDEBASE = 100000;

/**
 * Max domain name length.
 * @const {Number}
 * @default
 */

const MAX_NAME_SIZE = 255;

/**
 * Max label length.
 * @const {Number}
 * @default
 */

const MAX_LABEL_SIZE = 63;

/**
 * Max udp size.
 * @const {Number}
 * @default
 */

const MAX_UDP_SIZE = 512;

/**
 * Standard udp+edns size (rfc 2671).
 * @const {Number}
 * @default
 */

const STD_EDNS_SIZE = 1280;

/**
 * Max udp+edns size.
 * @const {Number}
 * @default
 */

const MAX_EDNS_SIZE = 4096;

/**
 * Max tcp size.
 * @const {Number}
 * @default
 */

const MAX_MSG_SIZE = 65535;

/**
 * Default DNS port.
 * @const {Number}
 * @default
 */

const DNS_PORT = 53;

/**
 * Default TTL.
 * @const {Number}
 * @default
 */

const DEFAULT_TTL = 3600;

/**
 * ICANN Root Trust Anchor (2010).
 * @const {String}
 * @see https://data.iana.org/root-anchors/root-anchors.xml
 */

const KSK_2010 = '. 172800 IN DS 19036 8 2'
  + ' 49AAC11D7B6F6446702E54A1607371607A1A41855200FD2CE1CDDE32F24E8FB5';

/**
 * ICANN Root Trust Anchor (2017).
 * @const {String}
 * @see https://data.iana.org/root-anchors/root-anchors.xml
 */

const KSK_2017 = '. 172800 IN DS 20326 8 2'
  + ' E06D44B80B8F1D39A95C0B0D7C65D08458E880409BBC683457104237C7F8EC8D';

/**
 * ICANN ARPA Trust Anchor
 * @const {String}
 */

const KSK_ARPA = 'arpa. 86400 IN DS 42581 8 2'
  + ' F28391C1ED4DC0F151EDD251A3103DCE0B9A5A251ACF6E24073771D71F3C40F9';

/*
 * Helpers
 */

function toSymbol(value, name, map, prefix, max, size) {
  if (typeof value !== 'number')
    throw new Error(`'${name}' must be a number.`);

  if ((value & max) !== value)
    throw new Error(`Invalid ${name}: ${value}.`);

  const symbol = map[value];

  if (typeof symbol === 'string')
    return symbol;

  return `${prefix}${value.toString(10)}`;
}

function fromSymbol(symbol, name, map, prefix, max, size) {
  if (typeof symbol !== 'string')
    throw new Error(`'${name}' must be a string.`);

  if (symbol.length > 64)
    throw new Error(`Unknown ${name}.`);

  const value = map[symbol];

  if (typeof value === 'number')
    return value;

  if (symbol.length <= prefix.length)
    throw new Error(`Unknown ${name}: ${symbol}.`);

  if (symbol.substring(0, prefix.length) !== prefix)
    throw new Error(`Unknown ${name}: ${symbol}.`);

  if (symbol.length > prefix.length + size)
    throw new Error(`Unknown ${name}: ${symbol}.`);

  let word = 0;

  for (let i = prefix.length; i < symbol.length; i++) {
    const ch = symbol.charCodeAt(i) - 0x30;

    if (ch < 0 || ch > 9)
      throw new Error(`Unknown ${name}: ${symbol}.`);

    word *= 10;
    word += ch;

    if (word > max)
      throw new Error(`Unknown ${name}: ${symbol}.`);
  }

  return word;
}

function isSymbol(symbol, name, map, prefix, max, size) {
  if (typeof symbol !== 'string')
    throw new Error(`'${name}' must be a string.`);

  try {
    fromSymbol(symbol, name, map, prefix, max, size);
    return true;
  } catch (e) {
    return false;
  }
}

function opcodeToString(opcode) {
  return toSymbol(opcode, 'opcode', opcodesByVal, 'OPCODE', 0x0f, 2);
}

function stringToOpcode(symbol) {
  return fromSymbol(symbol, 'opcode', opcodes, 'OPCODE', 0x0f, 2);
}

function isOpcodeString(symbol) {
  return isSymbol(symbol, 'opcode', opcodes, 'OPCODE', 0x0f, 2);
}

function codeToString(code) {
  return toSymbol(code, 'code', codesByVal, 'RCODE', 0x0f, 2);
}

function stringToCode(symbol) {
  return fromSymbol(symbol, 'code', codes, 'RCODE', 0x0fff, 4);
}

function isCodeString(symbol) {
  return isSymbol(symbol, 'code', codes, 'RCODE', 0x0fff, 4);
}

function typeToString(type) {
  return toSymbol(type, 'type', typesByVal, 'TYPE', 0xffff, 5);
}

function stringToType(symbol) {
  return fromSymbol(symbol, 'type', types, 'TYPE', 0xffff, 5);
}

function isTypeString(symbol) {
  return isSymbol(symbol, 'type', types, 'TYPE', 0xffff, 5);
}

function classToString(class_) {
  return toSymbol(class_, 'class', classesByVal, 'CLASS', 0xffff, 5);
}

function stringToClass(symbol) {
  return fromSymbol(symbol, 'class', classes, 'CLASS', 0xffff, 5);
}

function isClassString(symbol) {
  return isSymbol(symbol, 'class', classes, 'CLASS', 0xffff, 5);
}

function optionToString(option) {
  return toSymbol(option, 'option', optionsByVal, 'OPTION', 0xffff, 5);
}

function stringToOption(symbol) {
  return fromSymbol(symbol, 'option', options, 'OPTION', 0xffff, 5);
}

function isOptionString(symbol) {
  return isSymbol(symbol, 'option', options, 'OPTION', 0xffff, 5);
}

function algToString(alg) {
  return toSymbol(alg, 'algorithm', algsByVal, 'ALG', 0xff, 3);
}

function stringToAlg(symbol) {
  return fromSymbol(symbol, 'algorithm', algs, 'ALG', 0xff, 3);
}

function isAlgString(symbol) {
  return isSymbol(symbol, 'algorithm', algs, 'ALG', 0xff, 3);
}

function hashToString(hash) {
  return toSymbol(hash, 'hash', hashesByVal, 'HASH', 0xff, 3);
}

function stringToHash(symbol) {
  return fromSymbol(symbol, 'hash', hashes, 'HASH', 0xff, 3);
}

function isHashString(symbol) {
  return isSymbol(symbol, 'hash', hashes, 'HASH', 0xff, 3);
}

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
exports.eflags = eflags;
exports.eflagsByVal = eflagsByVal;
exports.options = options;
exports.optionsByVal = optionsByVal;
exports.keyFlags = keyFlags;
exports.algs = algs;
exports.algsByVal = algsByVal;
exports.hashes = hashes;
exports.hashesByVal = hashesByVal;
exports.algHashes = algHashes;
exports.nsecHashes = nsecHashes;
exports.nsecHashesByVal = nsecHashesByVal;
exports.certTypes = certTypes;
exports.certTypesByVal = certTypesByVal;
exports.usages = usages;
exports.usagesByVal = usagesByVal;
exports.selectors = selectors;
exports.selectorsByVal = selectorsByVal;
exports.matchingTypes = matchingTypes;
exports.matchingTypesByVal = matchingTypesByVal;
exports.sshAlgs = sshAlgs;
exports.sshAlgsByVal = sshAlgsByVal;
exports.sshHashes = sshHashes;
exports.sshHashesByVal = sshHashesByVal;
exports.tsigAlgs = tsigAlgs;
exports.tsigAlgsByVal = tsigAlgsByVal;
exports.tkeyModes = tkeyModes;
exports.tkeyModesByVal = tkeyModesByVal;

exports.YEAR68 = YEAR68;
exports.LOC_EQUATOR = LOC_EQUATOR;
exports.LOC_PRIMEMERIDIAN = LOC_PRIMEMERIDIAN;
exports.LOC_HOURS = LOC_HOURS;
exports.LOC_DEGREES = LOC_DEGREES;
exports.LOC_ALTITUDEBASE = LOC_ALTITUDEBASE;

exports.MAX_NAME_SIZE = MAX_NAME_SIZE;
exports.MAX_LABEL_SIZE = MAX_LABEL_SIZE;
exports.MAX_UDP_SIZE = MAX_UDP_SIZE;
exports.STD_EDNS_SIZE = STD_EDNS_SIZE;
exports.MAX_EDNS_SIZE = MAX_EDNS_SIZE;
exports.MAX_MSG_SIZE = MAX_MSG_SIZE;
exports.DNS_PORT = DNS_PORT;
exports.DEFAULT_TTL = DEFAULT_TTL;
exports.KSK_2010 = KSK_2010;
exports.KSK_2017 = KSK_2017;
exports.KSK_ARPA = KSK_ARPA;

exports.opcodeToString = opcodeToString;
exports.stringToOpcode = stringToOpcode;
exports.isOpcodeString = isOpcodeString;

exports.codeToString = codeToString;
exports.stringToCode = stringToCode;
exports.isCodeString = isCodeString;

exports.typeToString = typeToString;
exports.stringToType = stringToType;
exports.isTypeString = isTypeString;

exports.classToString = classToString;
exports.stringToClass = stringToClass;
exports.isClassString = isClassString;

exports.optionToString = optionToString;
exports.stringToOption = stringToOption;
exports.isOptionString = isOptionString;

exports.algToString = algToString;
exports.stringToAlg = stringToAlg;
exports.isAlgString = isAlgString;

exports.hashToString = hashToString;
exports.stringToHash = stringToHash;
exports.isHashString = isHashString;

exports._toSymbol = toSymbol;
exports._fromSymbol = fromSymbol;
exports._isSymbol = isSymbol;
