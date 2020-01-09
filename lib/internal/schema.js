/*!
 * schema.js - schemas for bns
 * Copyright (c) 2018, Christopher Jeffrey (MIT License).
 * https://github.com/chjj/bns
 *
 * Parts of this software are based on miekg/dns and golang/go:
 *   https://github.com/miekg/dns/blob/master/msg.go
 *   https://github.com/miekg/dns/blob/master/types.go
 *   https://github.com/golang/go/blob/master/src/net/dnsmsg.go
 */

/* eslint spaced-comment: 0 */

'use strict';

const assert = require('bsert');
const IP = require('binet');
const base32 = require('bs32');
const bio = require('bufio');
const constants = require('../constants');
const encoding = require('../encoding');
const lazy = require('./lazy');
const util = require('../util');

const {
  types,
  options,
  typeToString,
  stringToType,
  LOC_EQUATOR,
  LOC_PRIMEMERIDIAN,
  LOC_HOURS,
  LOC_DEGREES,
  LOC_ALTITUDEBASE
} = constants;

/*
 * Types
 */

const NAME = 0;
const SERVERS = 1;
const INET4 = 2;
const INET6 = 3;
const INET = 4;
const TARGET = 5;
const HEX = 6;
const HEXEND = 7;
const BASE32 = 8;
const BASE64 = 9;
const BASE64END = 10;
const CHAR = 11;
const OCTET = 12;
const TXT = 13;
const NSEC = 14;
const TAGS = 15;
const TIME = 16;
const TYPE = 17;
const U8 = 18;
const U16 = 19;
const U32 = 20;
const U48 = 21;
const U64 = 22;
const NID32 = 23;
const NID64 = 24;
const EUI48 = 25;
const EUI64 = 26;
const APL = 27;
const NSAP = 28;
const ATMA = 29;
const PROTOCOL = 30;
const WKS = 31;
const TTL = 32;

/*
 * Schemas
 */

const UNKNOWNSchema = [
  ['data', HEXEND]
];

const ASchema = [
  ['address', INET4]
];

const NSSchema = [
  ['ns', NAME]
];

const MDSchema = [
  ['md', NAME]
];

const MFSchema = [
  ['md', NAME]
];

const CNAMESchema = [
  ['target', NAME]
];

const SOASchema = [
  ['ns', NAME],
  ['mbox', NAME],
  ['serial', U32],
  ['refresh', TTL],
  ['retry', TTL],
  ['expire', TTL],
  ['minttl', TTL]
];

const MBSchema = [
  ['mb', NAME]
];

const MGSchema = [
  ['mg', NAME]
];

const MRSchema = [
  ['mr', NAME]
];

const NULLSchema = UNKNOWNSchema;

const WKSSchema = [
  ['address', INET4],
  ['protocol', PROTOCOL],
  ['bitmap', WKS]
];

const PTRSchema = [
  ['ptr', NAME]
];

const HINFOSchema = [
  ['cpu', CHAR],
  ['os', CHAR]
];

const MINFOSchema = [
  ['rmail', NAME],
  ['email', NAME]
];

const MXSchema = [
  ['preference', U16],
  ['mx', NAME]
];

const TXTSchema = [
  ['txt', TXT]
];

const RPSchema = [
  ['mbox', NAME],
  ['txt', NAME]
];

const AFSDBSchema = [
  ['subtype', U16],
  ['hostname', NAME]
];

const X25Schema = [
  ['psdnAddress', OCTET]
];

const ISDNSchema = [
  ['address', OCTET],
  ['sa', OCTET]
];

const RTSchema = [
  ['preference', U16],
  ['host', NAME]
];

const NSAPSchema = [
  ['nsap', NSAP]
];

const NSAPPTRSchema = PTRSchema;

const SIGSchema = [
  ['typeCovered', U16],
  ['algorithm', U8],
  ['labels', U8],
  ['origTTL', U32],
  ['expiration', TIME],
  ['inception', TIME],
  ['keyTag', U16],
  ['signerName', NAME],
  ['signature', BASE64END]
];

const KEYSchema = [
  ['flags', U16],
  ['protocol', U8],
  ['algorithm', U8],
  ['publicKey', BASE64END]
];

const PXSchema = [
  ['preference', U16],
  ['map822', NAME],
  ['mapx400', NAME]
];

const GPOSSchema = [
  ['longitude', OCTET],
  ['latitude', OCTET],
  ['altitude', OCTET]
];

const AAAASchema = [
  ['address', INET6]
];

const LOCSchema = [
  ['version', U8],
  ['size', U8],
  ['horizPre', U8],
  ['vertPre', U8],
  ['latitude', U32],
  ['longitude', U32],
  ['altitude', U32]
];

const NXTSchema = [
  ['nextDomain', NAME],
  ['typeBitmap', NSEC]
];

const EIDSchema = [
  ['endpoint', HEXEND]
];

const NIMLOCSchema = [
  ['locator', HEXEND]
];

const SRVSchema = [
  ['priority', U16],
  ['weight', U16],
  ['port', U16],
  ['target', NAME]
];

const ATMASchema = [
  ['format', U8],
  ['address', ATMA]
];

const NAPTRSchema = [
  ['order', U16],
  ['preference', U16],
  ['flags', CHAR],
  ['service', CHAR],
  ['regexp', CHAR],
  ['replacement', NAME]
];

const KXSchema = [
  ['preference', U16],
  ['exchanger', NAME]
];

const CERTSchema = [
  ['certType', U16],
  ['keyTag', U16],
  ['algorithm', U8],
  ['certificate', BASE64END]
];

const A6Schema = [
  ['prefixLen', U8],
  ['address', U16],
  ['prefix', NAME]
];

const DNAMESchema = CNAMESchema;

const OPTSchema = UNKNOWNSchema;

const APLSchema = [
  ['items', APL]
];

const DSSchema = [
  ['keyTag', U16],
  ['algorithm', U8],
  ['digestType', U8],
  ['digest', HEXEND]
];

const SSHFPSchema = [
  ['algorithm', U8],
  ['digestType', U8],
  ['fingerprint', HEXEND]
];

const IPSECKEYSchema = [
  ['precedence', U8],
  ['gatewayType', U8],
  ['algorithm', U8],
  ['target', TARGET],
  ['publicKey', BASE64END]
];

const RRSIGSchema = [
  ['typeCovered', TYPE],
  ['algorithm', U8],
  ['labels', U8],
  ['origTTL', U32],
  ['expiration', TIME],
  ['inception', TIME],
  ['keyTag', U16],
  ['signerName', NAME],
  ['signature', BASE64END]
];

const NSECSchema = [
  ['nextDomain', NAME],
  ['typeBitmap', NSEC]
];

const DNSKEYSchema = KEYSchema;

const DHCIDSchema = [
  ['digest', BASE64END]
];

const NSEC3Schema = [
  ['hash', U8],
  ['flags', U8],
  ['iterations', U16],
  ['salt', HEX],
  ['nextDomain', BASE32],
  ['typeBitmap', NSEC]
];

const NSEC3PARAMSchema = [
  ['hash', U8],
  ['flags', U8],
  ['iterations', U16],
  ['salt', HEXEND]
];

const TLSASchema = [
  ['usage', U8],
  ['selector', U8],
  ['matchingType', U8],
  ['certificate', HEXEND]
];

const SMIMEASchema = TLSASchema;

const HIPSchema = [
  ['algorithm', U8],
  ['hit', HEX],
  ['publicKey', BASE64],
  ['servers', SERVERS]
];

const NINFOSchema = [
  ['zsData', TXT]
];

const RKEYSchema = KEYSchema;

const TALINKSchema = [
  ['prevName', NAME],
  ['nextName', NAME]
];

const CDSSchema = DSSchema;

const CDNSKEYSchema = DNSKEYSchema;

const OPENPGPKEYSchema = [
  ['publicKey', BASE64END]
];

const CSYNCSchema = [
  ['serial', U32],
  ['flags', U16],
  ['typeBitmap', NSEC]
];

const SPFSchema = TXTSchema;

const UINFOSchema = [
  ['uinfo', CHAR]
];

const UIDSchema = [
  ['uid', U32]
];

const GIDSchema = [
  ['gid', U32]
];

const UNSPECSchema = UNKNOWNSchema;

const NIDSchema = [
  ['preference', U16],
  ['nodeID', NID64]
];

const L32Schema = [
  ['preference', U16],
  ['locator32', NID32]
];

const L64Schema = [
  ['preference', U16],
  ['locator64', NID64]
];

const LPSchema = [
  ['preference', U16],
  ['fqdn', NAME]
];

const EUI48Schema = [
  ['address', EUI48]
];

const EUI64Schema = [
  ['address', EUI64]
];

const TKEYSchema = [
  ['algorithm', NAME],
  ['inception', U32],
  ['expiration', U32],
  ['mode', U16],
  ['error', U16],
  ['key', HEX],
  ['other', HEXEND]
];

const TSIGSchema = [
  ['algorithm', NAME],
  ['timeSigned', TIME],
  ['fudge', U16],
  ['mac', HEX],
  ['origID', U16],
  ['error', U16],
  ['other', HEXEND]
];

const URISchema = [
  ['priority', U16],
  ['weight', U16],
  ['target', OCTET]
];

const CAASchema = [
  ['flag', U8],
  ['tag', OCTET],
  ['value', CHAR]
];

const AVCSchema = TXTSchema;

const DOASchema = [
  ['enterprise', U32],
  ['doa', U32],
  ['location', U8],
  ['mediaType', CHAR],
  ['data', BASE64END]
];

const TASchema = [
  ['keyTag', U16],
  ['algorithm', U8],
  ['digestType', U8],
  ['digest', HEXEND]
];

const DLVSchema = DSSchema;

const LLQSchema = [
  ['version', U16],
  ['opcode', U16],
  ['error', U16],
  ['id', HEX],
  ['leaseLife', U32]
];

const ULSchema = [
  ['lease', U32]
];

const NSIDSchema = [
  ['nsid', HEXEND]
];

const DAUSchema = [
  ['algCode', HEXEND]
];

const DHUSchema = DAUSchema;

const N3USchema = DAUSchema;

const SUBNETSchema = [
  ['family', U16],
  ['sourceNetmask', U8],
  ['sourceScope', U8],
  ['address', HEXEND]
];

const EXPIRESchema = [
  ['expire', U32]
];

const COOKIESchema = [
  ['cookie', HEXEND]
];

const TCPKEEPALIVESchema = [
  ['length', U16],
  ['timeout', U16]
];

const PADDINGSchema = [
  ['padding', HEXEND]
];

const CHAINSchema = [
  ['trustPoint', NAME]
];

const KEYTAGSchema = [
  ['tags', TAGS]
];

const LOCALSchema = [
  ['data', HEXEND]
];

/**
 * Record Schemas By Value
 * @const {Object}
 * @default
 */

const records = {
  [types.UNKNOWN]: UNKNOWNSchema,
  [types.A]: ASchema,
  [types.NS]: NSSchema,
  [types.MD]: MDSchema,
  [types.MF]: MFSchema,
  [types.CNAME]: CNAMESchema,
  [types.SOA]: SOASchema,
  [types.MB]: MBSchema,
  [types.MG]: MGSchema,
  [types.MR]: MRSchema,
  [types.NULL]: NULLSchema,
  [types.WKS]: WKSSchema,
  [types.PTR]: PTRSchema,
  [types.HINFO]: HINFOSchema,
  [types.MINFO]: MINFOSchema,
  [types.MX]: MXSchema,
  [types.TXT]: TXTSchema,
  [types.RP]: RPSchema,
  [types.AFSDB]: AFSDBSchema,
  [types.X25]: X25Schema,
  [types.ISDN]: ISDNSchema,
  [types.RT]: RTSchema,
  [types.NSAP]: NSAPSchema,
  [types.NSAPPTR]: NSAPPTRSchema,
  [types.SIG]: SIGSchema,
  [types.KEY]: KEYSchema,
  [types.PX]: PXSchema,
  [types.GPOS]: GPOSSchema,
  [types.AAAA]: AAAASchema,
  [types.LOC]: LOCSchema,
  [types.NXT]: NXTSchema,
  [types.EID]: EIDSchema,
  [types.NIMLOC]: NIMLOCSchema,
  [types.SRV]: SRVSchema,
  [types.ATMA]: ATMASchema,
  [types.NAPTR]: NAPTRSchema,
  [types.KX]: KXSchema,
  [types.CERT]: CERTSchema,
  [types.A6]: A6Schema,
  [types.DNAME]: DNAMESchema,
  [types.SINK]: null,
  [types.OPT]: OPTSchema,
  [types.APL]: APLSchema,
  [types.DS]: DSSchema,
  [types.SSHFP]: SSHFPSchema,
  [types.IPSECKEY]: IPSECKEYSchema,
  [types.RRSIG]: RRSIGSchema,
  [types.NSEC]: NSECSchema,
  [types.DNSKEY]: DNSKEYSchema,
  [types.DHCID]: DHCIDSchema,
  [types.NSEC3]: NSEC3Schema,
  [types.NSEC3PARAM]: NSEC3PARAMSchema,
  [types.TLSA]: TLSASchema,
  [types.SMIMEA]: SMIMEASchema,
  [types.HIP]: HIPSchema,
  [types.NINFO]: NINFOSchema,
  [types.RKEY]: RKEYSchema,
  [types.TALINK]: TALINKSchema,
  [types.CDS]: CDSSchema,
  [types.CDNSKEY]: CDNSKEYSchema,
  [types.OPENPGPKEY]: OPENPGPKEYSchema,
  [types.CSYNC]: CSYNCSchema,
  [types.SPF]: SPFSchema,
  [types.UINFO]: UINFOSchema,
  [types.UID]: UIDSchema,
  [types.GID]: GIDSchema,
  [types.UNSPEC]: UNSPECSchema,
  [types.NID]: NIDSchema,
  [types.L32]: L32Schema,
  [types.L64]: L64Schema,
  [types.LP]: LPSchema,
  [types.EUI48]: EUI48Schema,
  [types.EUI64]: EUI64Schema,
  [types.TKEY]: TKEYSchema,
  [types.TSIG]: TSIGSchema,
  [types.URI]: URISchema,
  [types.CAA]: CAASchema,
  [types.AVC]: AVCSchema,
  [types.DOA]: DOASchema,
  [types.IXFR]: null,
  [types.AXFR]: null,
  [types.MAILB]: null,
  [types.MAILA]: null,
  [types.ANY]: null,
  [types.TA]: TASchema,
  [types.DLV]: DLVSchema,
  [types.RESERVED]: null
};

/**
 * EDNS0 Option Classes By Value
 * @const {Object}
 */

const opts = {
  [options.RESERVED]: UNKNOWNSchema,
  [options.LLQ]: LLQSchema,
  [options.UL]: ULSchema,
  [options.NSID]: NSIDSchema,
  [options.DAU]: DAUSchema,
  [options.DHU]: DHUSchema,
  [options.N3U]: N3USchema,
  [options.SUBNET]: SUBNETSchema,
  [options.EXPIRE]: EXPIRESchema,
  [options.COOKIE]: COOKIESchema,
  [options.TCPKEEPALIVE]: TCPKEEPALIVESchema,
  [options.PADDING]: PADDINGSchema,
  [options.CHAIN]: CHAINSchema,
  [options.KEYTAG]: KEYTAGSchema,
  [options.LOCAL]: LOCALSchema,
  [options.LOCALSTART]: LOCALSchema,
  [options.LOCALEND]: LOCALSchema
};

/*
 * Encoding
 */

function toString(wire, rd, schema) {
  assert(wire && typeof wire.fromZone === 'function');
  assert(rd && typeof rd === 'object');
  assert(Array.isArray(schema));

  // Special case.
  if (schema === LOCSchema)
    return serializeLOC(rd);

  const str = [];

  for (let i = 0; i < schema.length; i++) {
    const [name, type] = schema[i];
    const value = rd[name];
    str.push(writeString(wire, rd, type, value));
  }

  return str.join(' ');
}

function writeString(wire, rd, type, value) {
  assert((type >>> 0) === type);

  switch (type) {
    case NAME: {
      assert(typeof value === 'string');
      return value;
    }

    case SERVERS: {
      assert(Array.isArray(value));
      return value.join(' ');
    }

    case INET4: {
      assert(typeof value === 'string');
      return value;
    }

    case INET6: {
      assert(typeof value === 'string');
      return value;
    }

    case INET: {
      assert(typeof value === 'string');
      return value;
    }

    case TARGET: {
      assert(typeof value === 'string');
      return value;
    }

    case HEX: {
      assert(Buffer.isBuffer(value));

      if (value.length === 0)
        return '-';

      return value.toString('hex').toUpperCase();
    }

    case HEXEND: {
      assert(Buffer.isBuffer(value));

      if (value.length === 0)
        return '-';

      const hex = value.toString('hex').toUpperCase();
      const chunks = [];

      for (let i = 0; i < hex.length; i += 56)
        chunks.push(hex.substring(i, i + 56));

      return chunks.join(' ');
    }

    case BASE32: {
      assert(Buffer.isBuffer(value));

      if (value.length === 0)
        return '-';

      return base32.encodeHex(value).toUpperCase();
    }

    case BASE64: {
      assert(Buffer.isBuffer(value));

      if (value.length === 0)
        return '-';

      return value.toString('base64');
    }

    case BASE64END: {
      assert(Buffer.isBuffer(value));

      if (value.length === 0)
        return '-';

      const b64 = value.toString('base64');
      const chunks = [];

      for (let i = 0; i < b64.length; i += 56)
        chunks.push(b64.substring(i, i + 56));

      return chunks.join(' ');
    }

    case CHAR: {
      assert(typeof value === 'string');
      return quote(value);
    }

    case OCTET: {
      assert(typeof value === 'string');
      return value;
    }

    case TXT: {
      assert(Array.isArray(value));

      const chunks = [];

      for (const str of value)
        chunks.push(quote(str));

      return chunks.join(' ');
    }

    case NSEC: {
      assert(Buffer.isBuffer(value));

      const types = encoding.fromBitmap(value);
      const parts = [];

      for (const type of types)
        parts.push(typeToString(type));

      return parts.join(' ');
    }

    case TAGS: {
      assert(Array.isArray(value));
      return value.join(' ');
    }

    case TIME: {
      return util.serializeTime(value);
    }

    case TYPE: {
      return typeToString(value);
    }

    case U8: {
      assert((value & 0xff) === value);
      return value.toString(10);
    }

    case U16: {
      assert((value & 0xffff) === value);
      return value.toString(10);
    }

    case U32: {
      assert((value >>> 0) === value);
      return value.toString(10);
    }

    case U48: {
      assert(Number.isSafeInteger(value));
      assert(value >= 0 && value <= 0xffffffffffff);
      return value.toString(10);
    }

    case U64: {
      assert(Buffer.isBuffer(value) && value.length === 8);
      const hi = bio.readU32BE(value, 0);
      const lo = bio.readU32BE(value, 4);
      return util.serializeU64(hi, lo);
    }

    case NID32: {
      return serializeNID32(value);
    }

    case NID64: {
      return serializeNID64(value);
    }

    case EUI48: {
      return serializeEUI(value, 6);
    }

    case EUI64: {
      return serializeEUI(value, 8);
    }

    case APL: {
      assert(Array.isArray(value));

      const parts = [];

      for (const ap of value)
        parts.push(ap.toString());

      return parts.join(' ');
    }

    case NSAP: {
      return serializeNSAP(value);
    }

    case ATMA: {
      return serializeATMA(value, rd.format);
    }

    case PROTOCOL: {
      return serializeProtocol(value);
    }

    case WKS: {
      return serializeWKS(value);
    }

    case TTL: {
      assert((value >>> 0) === value);
      return value.toString(10);
    }

    default: {
      throw new Error('Unknown type.');
    }
  }
}

function fromJSON(wire, rd, schema, json) {
  assert(wire && typeof wire.fromZone === 'function');
  assert(rd && typeof rd === 'object');
  assert(Array.isArray(schema));
  assert(json && typeof json === 'object');

  for (let i = 0; i < schema.length; i++) {
    const [name, type] = schema[i];
    rd[name] = readJSON(wire, rd, type, json[name]);
  }

  return rd;
}

function toJSON(wire, rd, schema) {
  assert(wire && typeof wire.fromZone === 'function');
  assert(rd && typeof rd === 'object');
  assert(Array.isArray(schema));

  const json = {};

  for (let i = 0; i < schema.length; i++) {
    const [name, type] = schema[i];
    json[name] = writeJSON(wire, rd, type, rd[name]);
  }

  return json;
}

function readJSON(wire, rd, type, value) {
  assert((type >>> 0) === type);

  switch (type) {
    case NAME: {
      assert(encoding.isName(value));
      return value;
    }

    case SERVERS: {
      assert(Array.isArray(value));

      const names = [];

      for (const name of value) {
        assert(encoding.isName(name));
        names.push(name);
      }

      return names;
    }

    case INET4: {
      const ip = IP.toBuffer(value);

      assert(IP.isIPv4(ip));

      return IP.toString(ip);
    }

    case INET6: {
      const ip = IP.toBuffer(value);

      if (IP.isIPv4(ip))
        return `::ffff:${IP.toString(ip)}`;

      return IP.toString(ip);
    }

    case INET: {
      return IP.normalize(value);
    }

    case TARGET: {
      assert(typeof value === 'string');

      try {
        return IP.normalize(value);
      } catch (e) {
        ;
      }

      if (!encoding.isName(value))
        throw new Error('Invalid target.');

      return value;
    }

    case HEX:
    case HEXEND: {
      return util.parseHex(value);
    }

    case BASE32: {
      return base32.decodeHex(value);
    }

    case BASE64:
    case BASE64END: {
      return util.parseB64(value);
    }

    case CHAR: {
      assert(encoding.isString(value, false));
      return value;
    }

    case OCTET: {
      assert(encoding.isString(value, true));
      return value;
    }

    case TXT: {
      assert(Array.isArray(value));

      const txt = [];

      for (const str of value) {
        assert(encoding.isString(str, false));
        txt.push(str);
      }

      return txt;
    }

    case NSEC: {
      return encoding.toBitmap(value);
    }

    case TAGS: {
      assert(Array.isArray(value));

      const tags = [];

      for (const tag of value) {
        assert((tag & 0xffff) === tag);
        tags.push(tag);
      }

      return tags;
    }

    case TIME: {
      assert(Number.isSafeInteger(value));
      assert(value >= 0 && value <= 0xffffffffffff);
      return value;
    }

    case TYPE: {
      return stringToType(value);
    }

    case U8: {
      assert((value & 0xff) === value);
      return value;
    }

    case U16: {
      assert((value & 0xffff) === value);
      return value;
    }

    case U32: {
      assert((value >>> 0) === value);
      return value;
    }

    case U48: {
      assert(Number.isSafeInteger(value));
      assert(value >= 0 && value <= 0xffffffffffff);
      return value;
    }

    case U64: {
      assert(typeof value === 'string');
      assert(value.length === 16);
      return util.parseHex(value);
    }

    case NID32: {
      assert(typeof value === 'string');
      assert(value.length === 8);
      return util.parseHex(value);
    }

    case NID64: {
      assert(typeof value === 'string');
      assert(value.length === 16);
      return util.parseHex(value);
    }

    case EUI48: {
      assert(typeof value === 'string');
      assert(value.length === 12);
      return util.parseHex(value);
    }

    case EUI64: {
      assert(typeof value === 'string');
      assert(value.length === 16);
      return util.parseHex(value);
    }

    case APL: {
      assert(Array.isArray(value));

      const {AP} = wire;
      const items = [];

      for (const json of value)
        items.push(AP.fromJSON(json));

      return items;
    }

    case NSAP: {
      return util.parseHex(value);
    }

    case ATMA: {
      return util.parseHex(value);
    }

    case PROTOCOL: {
      assert((value & 0xff) === value);
      return value;
    }

    case WKS: {
      return util.parseHex(value);
    }

    case TTL: {
      assert((value >>> 0) === value);
      return value;
    }

    default: {
      throw new Error('Unknown type.');
    }
  }
}

function writeJSON(wire, rd, type, value) {
  assert((type >>> 0) === type);

  switch (type) {
    case NAME: {
      assert(typeof value === 'string');
      return value;
    }

    case SERVERS: {
      assert(Array.isArray(value));
      return value;
    }

    case INET4: {
      assert(typeof value === 'string');
      return value;
    }

    case INET6: {
      assert(typeof value === 'string');
      return value;
    }

    case INET: {
      assert(typeof value === 'string');
      return value;
    }

    case TARGET: {
      assert(typeof value === 'string');
      return value;
    }

    case HEX:
    case HEXEND: {
      assert(Buffer.isBuffer(value));
      return value.toString('hex');
    }

    case BASE32: {
      assert(Buffer.isBuffer(value));
      return base32.encodeHex(value);
    }

    case BASE64:
    case BASE64END: {
      assert(Buffer.isBuffer(value));
      return value.toString('base64');
    }

    case CHAR: {
      assert(typeof value === 'string');
      return value;
    }

    case OCTET: {
      assert(typeof value === 'string');
      return value;
    }

    case TXT: {
      assert(Array.isArray(value));
      return value;
    }

    case NSEC: {
      return encoding.fromBitmap(value);
    }

    case TAGS: {
      assert(Array.isArray(value));
      return value;
    }

    case TIME: {
      assert(Number.isSafeInteger(value));
      assert(value >= 0 && value <= 0xffffffffffff);
      return value;
    }

    case TYPE: {
      assert(typeof value === 'number');
      return typeToString(value);
    }

    case U8: {
      assert((value & 0xff) === value);
      return value;
    }

    case U16: {
      assert((value & 0xffff) === value);
      return value;
    }

    case U32: {
      assert((value >>> 0) === value);
      return value;
    }

    case U48: {
      assert(Number.isSafeInteger(value));
      assert(value >= 0 && value <= 0xffffffffffff);
      return value;
    }

    case U64: {
      assert(Buffer.isBuffer(value) && value.length === 8);
      return value.toString('hex');
    }

    case NID32: {
      assert(Buffer.isBuffer(value) && value.length === 4);
      return value.toString('hex');
    }

    case NID64: {
      assert(Buffer.isBuffer(value) && value.length === 8);
      return value.toString('hex');
    }

    case EUI48: {
      assert(Buffer.isBuffer(value) && value.length === 6);
      return value.toString('hex');
    }

    case EUI64: {
      assert(Buffer.isBuffer(value) && value.length === 8);
      return value.toString('hex');
    }

    case APL: {
      assert(Array.isArray(value));

      const items = [];

      for (const ap of value)
        items.push(ap.toJSON());

      return items;
    }

    case NSAP: {
      assert(Buffer.isBuffer(value));
      return value.toString('hex');
    }

    case ATMA: {
      assert(Buffer.isBuffer(value));
      return value.toString('hex');
    }

    case PROTOCOL: {
      assert((value & 0xff) === value);
      return value;
    }

    case WKS: {
      assert(Buffer.isBuffer(value));
      return value.toString('hex');
    }

    case TTL: {
      assert((value >>> 0) === value);
      return value;
    }

    default: {
      throw new Error('Unknown type.');
    }
  }
}

/*
 * Helpers
 */

function quote(str) {
  assert(typeof str === 'string');
  return `"${str}"`;
}

function serializeNID32(data) {
  assert(Buffer.isBuffer(data));

  if (data.length !== 4)
    throw new Error('Invalid NID32.');

  return IP.toString(data);
}

function serializeNID64(data) {
  assert(Buffer.isBuffer(data));

  if (data.length !== 8)
    throw new Error('Invalid NID32.');

  const ip = util.padRight(data, 16);
  const str = IP.toString(ip);

  if (str[str.length - 1] !== ':')
    throw new Error('Invalid NID32.');

  if (str[str.length - 2] !== ':')
    throw new Error('Invalid NID32.');

  if (str.length === 2)
    return str;

  return str.slice(0, -2);
}

function serializeEUI(data, size) {
  assert(Buffer.isBuffer(data));
  assert(size === 6 || size === 8);

  if (data.length !== size)
    throw new Error('Invalid EUI.');

  const hex = data.toString('hex');

  let str = '';

  for (let i = 0; i < hex.length; i += 2) {
    str += hex.substring(i, i + 2);
    if (i !== hex.length - 2)
      str += '-';
  }

  return str;
}

function serializeNSAP(data) {
  assert(Buffer.isBuffer(data));
  return `0x${data.toString('hex')}`;
}

function serializeATMA(data, format) {
  assert(Buffer.isBuffer(data));

  switch (format) {
    case 0:
      // Note: no leading 0x.
      return data.toString('hex');
    case 1:
      return data.toString('ascii');
    default:
      return data.toString('hex');
  }
}

function serializeProtocol(value) {
  const iana = lazy('./iana');
  return iana.protocolToString(value);
}

function serializeWKS(map) {
  assert(Buffer.isBuffer(map));

  const iana = lazy('./iana');
  const ports = encoding.fromPortmap(map);
  const services = [];

  for (const port of ports) {
    const service = iana.getService(port);
    if (service)
      services.push(service);
  }

  return services.join(' ');
}

function cmToM(m, e) {
  assert((m & 0xff) === m);
  assert((e & 0xff) === e);

  if (e < 2) {
    if (e === 1)
      m *= 10;

    m = m.toString(10);

    if (m.length < 2)
      m = '0' + m;

    return `0.${m}`;
  }

  let s = m.toString(10);

  while (e > 2) {
    s += '0';
    e -= 1;
  }

  return s;
}

function serializeLOC(rd) {
  assert(rd && typeof rd === 'object');

  let str = '';

  // North.
  let lat = rd.latitude;
  let ns = 'N';

  if (lat > LOC_EQUATOR) {
    lat = lat - LOC_EQUATOR;
  } else {
    ns = 'S';
    lat = LOC_EQUATOR - lat;
  }

  const lh = (lat / LOC_DEGREES) >>> 0;
  lat %= LOC_DEGREES;

  const lm = (lat / LOC_HOURS) >>> 0;
  lat %= LOC_HOURS;

  const ls = lat / 1000;

  str += lh.toString(10);
  str += ' ';
  str += lm.toString(10);
  str += ' ';
  str += ls.toFixed(3);
  str += ' ';
  str += ns;
  str += ' ';

  // East.
  let lon = rd.longitude;
  let ew = 'E';

  if (lon > LOC_PRIMEMERIDIAN) {
    lon = lon - LOC_PRIMEMERIDIAN;
  } else {
    ew = 'W';
    lon = LOC_PRIMEMERIDIAN - lon;
  }

  const gh = (lon / LOC_DEGREES) >>> 0;
  lon %= LOC_DEGREES;

  const gm = (lon / LOC_HOURS) >>> 0;
  lon %= LOC_HOURS;

  const gs = lon / 1000;

  str += gh.toString(10);
  str += ' ';
  str += gm.toString(10);
  str += ' ';
  str += gs.toFixed(3);
  str += ' ';
  str += ew;
  str += ' ';

  // Altitude.
  let alt = rd.altitude / 100;
  alt -= LOC_ALTITUDEBASE;

  str += alt.toFixed(2);
  str += 'm ';

  // Params.
  str += cmToM((rd.size & 0xf0) >>> 4, rd.size & 0x0f) + 'm ';
  str += cmToM((rd.horizPre & 0xf0) >>> 4, rd.horizPre & 0x0f) + 'm ';
  str += cmToM((rd.vertPre & 0xf0) >>> 4, rd.vertPre & 0x0f) + 'm';

  return str;
}

/*
 * Expose
 */

exports.NAME = NAME;
exports.SERVERS = SERVERS;
exports.INET4 = INET4;
exports.INET6 = INET6;
exports.INET = INET;
exports.TARGET = TARGET;
exports.HEX = HEX;
exports.HEXEND = HEXEND;
exports.BASE32 = BASE32;
exports.BASE64 = BASE64;
exports.BASE64END = BASE64END;
exports.CHAR = CHAR;
exports.OCTET = OCTET;
exports.TXT = TXT;
exports.NSEC = NSEC;
exports.TAGS = TAGS;
exports.TIME = TIME;
exports.TYPE = TYPE;
exports.U8 = U8;
exports.U16 = U16;
exports.U32 = U32;
exports.U48 = U48;
exports.U64 = U64;
exports.NID32 = NID32;
exports.NID64 = NID64;
exports.EUI48 = EUI48;
exports.EUI64 = EUI64;
exports.APL = APL;
exports.NSAP = NSAP;
exports.ATMA = ATMA;
exports.PROTOCOL = PROTOCOL;
exports.WKS = WKS;
exports.TTL = TTL;

exports.records = records;
exports.options = opts;
exports.toString = toString;
exports.fromJSON = fromJSON;
exports.toJSON = toJSON;
