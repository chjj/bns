/*!
 * schema.js - schemas for bns
 * Copyright (c) 2018, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bns
 *
 * Parts of this software are based on miekg/dns and golang/go:
 *   https://github.com/miekg/dns/blob/master/msg.go
 *   https://github.com/miekg/dns/blob/master/types.go
 *   https://github.com/golang/go/blob/master/src/net/dnsmsg.go
 */

'use strict';

const assert = require('assert');
const IP = require('binet');
const base32 = require('bs32');
const util = require('./util');
const encoding = require('./encoding');
const constants = require('./constants');

const {
  types,
  YEAR68,
  options,
  typeToString,
  stringToType,
  typesByVal
} = constants;

/*
 * Constants
 */

const DUMMY = Buffer.alloc(0);

/*
 * Schemas
 */

const UNKNOWNSchema = [
  ['data', 'hex-end']
];

const ASchema = [
  ['address', 'inet4']
];

const NSSchema = [
  ['ns', 'name']
];

const MDSchema = [
  ['md', 'name']
];

const MFSchema = [
  ['md', 'name']
];

const CNAMESchema = [
  ['target', 'name']
];

const SOASchema = [
  ['ns', 'name'],
  ['mbox', 'name'],
  ['serial', 'u32'],
  ['refresh', 'u32'],
  ['retry', 'u32'],
  ['expire', 'u32'],
  ['minttl', 'u32']
];

const MBSchema = [
  ['mb', 'name']
];

const MGSchema = [
  ['mg', 'name']
];

const MRSchema = [
  ['mr', 'name']
];

const NULLSchema = UNKNOWNSchema;

const WKSSchema = [
  ['address', 'inet4'],
  ['protocol', 'u8'],
  ['bitmap', 'hex-end'] // ??
];

const PTRSchema = [
  ['ptr', 'name']
];

const HINFOSchema = [
  ['cpu', 'string'],
  ['os', 'string']
];

const MINFOSchema = [
  ['rmail', 'name'],
  ['email', 'name']
];

const MXSchema = [
  ['preference', 'u16'],
  ['mx', 'name']
];

const TXTSchema = [
  ['txt', 'txt']
];

const RPSchema = [
  ['mbox', 'name'],
  ['txt', 'name']
];

const AFSDBSchema = [
  ['subtype', 'u16'],
  ['hostname', 'name']
];

const X25Schema = [
  ['psdnAddress', 'string']
];

const ISDNSchema = [
  ['address', 'string'],
  ['sa', 'string']
];

const RTSchema = [
  ['preference', 'u16'],
  ['host', 'name']
];

const NSAPSchema = [
  ['nsap', 'hex-end'] // ??
];

const NSAPPTRSchema = PTRSchema;

const SIGSchema = [
  ['typeCovered', 'u16'],
  ['algorithm', 'u8'],
  ['labels', 'u8'],
  ['origTTL', 'u32'],
  ['expiration', 'time'],
  ['inception', 'time'],
  ['keyTag', 'u16'],
  ['signerName', 'name'],
  ['signature', 'base64-end']
];

const KEYSchema = [
  ['flags', 'u16'],
  ['protocol', 'u8'],
  ['algorithm', 'u8'],
  ['publicKey', 'base64-end']
];

const PXSchema = [
  ['preference', 'u16'],
  ['map822', 'name'],
  ['mapx400', 'name']
];

const GPOSSchema = [
  ['longitude', 'string'],
  ['latitude', 'string'],
  ['altitude', 'string']
];

const AAAASchema = [
  ['address', 'inet6']
];

const LOCSchema = [
  ['version', 'u8'],
  ['size', 'u8'],
  ['horizPre', 'u8'],
  ['vertPre', 'u8'],
  ['latitude', 'u32'],
  ['longitude', 'u32'],
  ['altitude', 'u32']
];

const NXTSchema = [
  ['nextDomain', 'name'],
  ['typeBitmap', 'nsec']
];

const EIDSchema = [
  ['endpoint', 'hex-end']
];

const NIMLOCSchema = [
  ['locator', 'hex-end']
];

const SRVSchema = [
  ['priority', 'u16'],
  ['weight', 'u16'],
  ['port', 'u16'],
  ['target', 'name']
];

const ATMASchema = [
  ['format', 'u8'],
  ['address', 'hex-end'] // ??
];

const NAPTRSchema = [
  ['order', 'u16'],
  ['preference', 'u16'],
  ['flags', 'string'],
  ['service', 'string'],
  ['regexp', 'string'],
  ['replacement', 'name']
];

const KXSchema = [
  ['preference', 'u16'],
  ['exchanger', 'name']
];

const CERTSchema = [
  ['certType', 'u16'],
  ['keyTag', 'u16'],
  ['algorithm', 'u8'],
  ['certificate', 'base64-end']
];

const A6Schema = [
  ['address', 'u16'],
  ['prefix', 'string']
];

const DNAMESchema = CNAMESchema;

const OPTSchema = UNKNOWNSchema;

const APLSchema = [
  ['family', 'u16'],
  ['prefix', 'u8'],
  ['n', 'u8'],
  ['afd', 'hex-end'] // ??
];

const DSSchema = [
  ['keyTag', 'u16'],
  ['algorithm', 'u8'],
  ['digestType', 'u8'],
  ['digest', 'hex-end']
];

const SSHFPSchema = [
  ['algorithm', 'u8'],
  ['digestType', 'u8'],
  ['fingerprint', 'hex-end']
];

const IPSECKEYSchema = [
  ['precedence', 'u8'],
  ['gatewayType', 'u8'],
  ['algorithm', 'u8'],
  ['target', 'string'],
  ['publicKey', 'base64-end']
];

const RRSIGSchema = [
  ['typeCovered', 'type'],
  ['algorithm', 'u8'],
  ['labels', 'u8'],
  ['origTTL', 'u32'],
  ['expiration', 'time'],
  ['inception', 'time'],
  ['keyTag', 'u16'],
  ['signerName', 'name'],
  ['signature', 'base64-end']
];

const NSECSchema = [
  ['nextDomain', 'name'],
  ['typeBitmap', 'nsec']
];

const DNSKEYSchema = KEYSchema;

const DHCIDSchema = [
  ['digest', 'base64-end']
];

const NSEC3Schema = [
  ['hash', 'u8'],
  ['flags', 'u8'],
  ['iterations', 'u16'],
  ['salt', 'hex'],
  ['nextDomain', 'base32'],
  ['typeBitmap', 'nsec']
];

const NSEC3PARAMSchema = [
  ['hash', 'u8'],
  ['flags', 'u8'],
  ['iterations', 'u16'],
  ['salt', 'hex']
];

const TLSASchema = [
  ['usage', 'u8'],
  ['selector', 'u8'],
  ['matchingType', 'u8'],
  ['certificate', 'hex-end']
];

const SMIMEASchema = TLSASchema;

const HIPSchema = [
  ['algorithm', 'u8'],
  ['hit', 'hex'],
  ['publicKey', 'base64'],
  ['servers', 'servers']
];

const NINFOSchema = [
  ['zsData', 'txt']
];

const RKEYSchema = KEYSchema;

const TALINKSchema = [
  ['prevName', 'name'],
  ['nextName', 'name']
];

const CDSSchema = DSSchema;

const CDNSKEYSchema = DNSKEYSchema;

const OPENPGPKEYSchema = [
  ['publicKey', 'base64-end']
];

const CSYNCSchema = [
  ['serial', 'u32'],
  ['flags', 'u16'],
  ['typeBitmap', 'nsec']
];

const SPFSchema = TXTSchema;

const UINFOSchema = [
  ['uinfo', 'string']
];

const UIDSchema = [
  ['uid', 'u32']
];

const GIDSchema = [
  ['gid', 'u32']
];

const UNSPECSchema = UNKNOWNSchema;

const NIDSchema = [
  ['preference', 'u16'],
  ['nodeID', 'u64']
];

const L32Schema = [
  ['preference', 'u16'],
  ['locator32', 'inet4']
];

const L64Schema = [
  ['preference', 'u16'],
  ['locator64', 'u64']
];

const LPSchema = [
  ['preference', 'u16'],
  ['fqdn', 'name']
];

const EUI48Schema = [
  ['address', 'u48']
];

const EUI64Schema = [
  ['address', 'u64']
];

const TKEYSchema = [
  ['algorithm', 'name'],
  ['inception', 'u32'],
  ['expiration', 'u32'],
  ['mode', 'u16'],
  ['error', 'u16'],
  ['key', 'hex'],
  ['other', 'hex']
];

const TSIGSchema = [
  ['algorithm', 'name'],
  ['timeSigned', 'u48'],
  ['fudge', 'u16'],
  ['mac', 'hex'],
  ['origID', 'u16'],
  ['error', 'u16'],
  ['other', 'hex']
];

const URISchema = [
  ['priority', 'u16'],
  ['weight', 'u16'],
  ['target', 'octet']
];

const CAASchema = [
  ['flag', 'u8'],
  ['tag', 'string'],
  ['value', 'octet']
];

const AVCSchema = TXTSchema;

const DOASchema = [
  ['enterprise', 'u32'],
  ['type', 'u32'],
  ['location', 'u8'],
  ['mediaType', 'octet'],
  ['data', 'base64-end']
];

const ANYSchema = UNKNOWNSchema;

const TASchema = [
  ['keyTag', 'u16'],
  ['algorithm', 'u8'],
  ['digestType', 'u8'],
  ['digest', 'hex-end']
];

const DLVSchema = DSSchema;

const LLQSchema = [
  ['version', 'u16'],
  ['opcode', 'u16'],
  ['error', 'u16'],
  ['id', 'hex'],
  ['leaseLife', 'u32']
];

const ULSchema = [
  ['lease', 'u32']
];

const NSIDSchema = [
  ['nsid', 'hex-end']
];

const DAUSchema = [
  ['algCode', 'hex-end']
];

const DHUSchema = DAUSchema;

const N3USchema = DAUSchema;

const SUBNETSchema = [
  ['family', 'u16'],
  ['sourceNetmask', 'u8'],
  ['sourceScope', 'u8'],
  ['address', 'string']
];

const EXPIRESchema = [
  ['expire', 'u32']
];

const COOKIESchema = [
  ['cookie', 'hex-end']
];

const TCPKEEPALIVESchema = [
  ['length', 'u16'],
  ['timeout', 'u16']
];

const PADDINGSchema = [
  ['padding', 'hex-end']
];

const CHAINSchema = [
  ['trustPoint', 'name']
];

const KEYTAGSchema = [
  ['tags', 'tags']
];

const LOCALSchema = [
  ['data', 'hex-end']
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
  [types.ANY]: ANYSchema,
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

function fromString(rd, schema, str) {
  assert(rd);
  assert(schema);
  assert(typeof str === 'string');

  const parts = str.trim().split(/\s+/);
  const len = Math.min(parts.length, schema.length);

  for (let i = 0; i < len; i++) {
    if (i >= schema.length)
      break;

    if (i >= parts.length)
      break;

    const [name, type] = schema[i];
    const part = parts[i];

    switch (type) {
      case 'hex-end':
      case 'base64-end':
      case 'servers':
      case 'nsec':
      case 'txt':
      case 'tags': {
        let j = i;

        for (; j < parts.length; j++) {
          const part = parts[j];
          if (part.length > 0 && part[0] === ';')
            break;
        }

        const left = parts.slice(i, j).join(' ');

        rd[name] = readType(type, left);

        i = len - 1;

        break;
      }
      case 'octet': {
        const start = i;

        let quote = false;
        let str = null;

        for (; i < parts.length; i++) {
          const part = parts[i];

          for (let j = 0; j < part.length; j++) {
            const ch = part[j];

            if (ch === '\\') {
              j += 1;
              continue;
            }

            if (ch === '"') {
              if (!quote) {
                assert(i === start);
                assert(j === 0);
                quote = true;
                continue;
              }
              assert(j === part.length - 1);
              str = parts.slice(start, i + 1).join(' ');
            }
          }

          if (str)
            break;
        }

        assert(str);

        rd[name] = readType(type, str);

        break;
      }
      default: {
        rd[name] = readType(type, part);
        break;
      }
    }
  }

  return rd;
}

function toString(rd, schema) {
  assert(rd);
  assert(schema);

  const str = [];

  for (let i = 0; i < schema.length; i++) {
    const [name, type] = schema[i];
    const value = rd[name];
    str.push(writeType(type, value));
  }

  return str.join(' ');
}

function readType(type, part) {
  switch (type) {
    case 'name': {
      assert(util.isName(part));
      return part;
    }
    case 'servers': {
      const names = part.split(' ');
      for (const name of names)
        assert(util.isName(name));
      return names;
    }
    case 'inet4': {
      assert(IP.isIPv4String(part));
      return IP.normalize(part);
    }
    case 'inet6': {
      assert(IP.isIPv6String(part));

      let ip = IP.normalize(part);

      if (IP.isIPv4String(ip))
        ip = `::ffff:${ip}`;

      return ip;
    }
    case 'hex': {
      if (part === '-')
        return DUMMY;
      const data = Buffer.from(part, 'hex');
      assert(data.length === (part.length >>> 1));
      return data;
    }
    case 'hex-end': {
      if (part === '-')
        return DUMMY;
      const hex = part.replace(/\s+/g, '');
      const data = Buffer.from(hex, 'hex');
      assert(data.length === (hex.length >>> 1));
      return data;
    }
    case 'base32': {
      if (part === '-')
        return DUMMY;
      return base32.decodeHex(part);
    }
    case 'base64': {
      if (part === '-')
        return DUMMY;
      assert(/^[A-Za-z0-9+\/=]+$/.test(part));
      return Buffer.from(part, 'base64');
    }
    case 'base64-end': {
      if (part === '-')
        return DUMMY;
      const b64 = part.replace(/\s+/g, '');
      assert(/^[A-Za-z0-9+\/=]+$/.test(b64));
      return Buffer.from(b64, 'base64');
    }
    case 'octet': {
      return JSON.parse(part);
    }
    case 'string': {
      return part;
    }
    case 'txt': {
      const out = [];

      let last = -1;

      for (let i = 0; i < part.length; i++) {
        const ch = part[i];

        if (ch === '\\') {
          i += 1;
          continue;
        }

        if (ch === '"') {
          if (last === -1) {
            last = i;
          } else {
            out.push(JSON.parse(part.substring(last, i)));
            last = -1;
          }
        }
      }

      if (last !== -1)
        throw new Error('Unclosed double quote.');

      return out;
    }
    case 'nsec': {
      const tns = part.split(' ');
      const ts = [];

      for (const tn of tns)
        ts.push(stringToType(tn));

      return encoding.toBitmap(ts);
    }
    case 'tags': {
      const tags = part.split(' ');
      const out = [];

      for (const tag of tags)
        out.push(util.parseU16(tag));

      return out;
    }
    case 'time': {
      return stringToTime(part);
    }
    case 'type': {
      return stringToType(part);
    }
    case 'u8': {
      return util.parseU8(part);
    }
    case 'u16': {
      return util.parseU16(part);
    }
    case 'u32': {
      return util.parseU32(part);
    }
    case 'u48': {
      return util.parseU48(part);
    }
    case 'u64': {
      const [hi, lo] = util.parseU64(part);
      const out = Buffer.allocUnsafe(8);
      out.writeUInt32BE(hi, true);
      out.writeUInt32BE(lo, true);
      return out;
    }
    default: {
      throw new Error('Unknown type.');
    }
  }
}

function writeType(type, value) {
  switch (type) {
    case 'name': {
      assert(typeof value === 'string');
      return value;
    }
    case 'servers': {
      assert(Array.isArray(value));
      return value.join(' ');
    }
    case 'inet4': {
      assert(typeof value === 'string');
      return value;
    }
    case 'inet6': {
      assert(typeof value === 'string');
      return value;
    }
    case 'hex': {
      assert(Buffer.isBuffer(value));
      if (value.length === 0)
        return '-';
      return value.toString('hex').toUpperCase();
    }
    case 'hex-end': {
      assert(Buffer.isBuffer(value));

      if (value.length === 0)
        return '-';

      const hex = value.toString('hex').toUpperCase();
      const out = [];

      for (let i = 0; i < hex.length; i += 56)
        out.push(hex.substring(i, i + 56));

      return out.join(' ');
    }
    case 'base32': {
      assert(Buffer.isBuffer(value));
      if (value.length === 0)
        return '-';
      return base32.encodeHex(value).toUpperCase();
    }
    case 'base64': {
      assert(Buffer.isBuffer(value));
      if (value.length === 0)
        return '-';
      return value.toString('base64');
    }
    case 'base64-end': {
      assert(Buffer.isBuffer(value));

      if (value.length === 0)
        return '-';

      const b64 = value.toString('base64');
      const out = [];

      for (let i = 0; i < b64.length; i += 56)
        out.push(b64.substring(i, i + 56));

      return out.join(' ');
    }
    case 'octet': {
      assert(typeof value === 'string');
      return JSON.stringify(value);
    }
    case 'string': {
      assert(typeof value === 'string');
      return value;
    }
    case 'txt': {
      assert(Array.isArray(value));

      const out = [];

      for (const str of value)
        out.push(JSON.stringify(str));

      return out.join(' ');
    }
    case 'nsec': {
      assert(Buffer.isBuffer(value));

      const ts = encoding.fromBitmap(value);
      const tns = [];

      for (const t of ts) {
        if (typesByVal[t])
          tns.push(typeToString(t));
      }

      return tns.join(' ');
    }
    case 'tags': {
      assert(Array.isArray(value));
      return value.join(' ');
    }
    case 'time': {
      return timeToString(value);
    }
    case 'type': {
      return typeToString(value);
    }
    case 'u8': {
      assert((value & 0xff) === value);
      return value.toString(10);
    }
    case 'u16': {
      assert((value & 0xffff) === value);
      return value.toString(10);
    }
    case 'u32': {
      assert((value >>> 0) === value);
      return value.toString(10);
    }
    case 'u48': {
      assert(Number.isSafeInteger(value));
      assert(value >= 0 && value <= 0xffffffffffff);
      return value.toString(10);
    }
    case 'u64': {
      assert(Buffer.isBuffer(value) && value.length === 8);
      const hi = value.readUInt32BE(0, true);
      const lo = value.readUInt32BE(4, true);
      return util.serializeU64(hi, lo);
    }
    default: {
      throw new Error('Unknown type.');
    }
  }
}

function fromJSON(rd, schema, json) {
  assert(rd);
  assert(schema);
  assert(json && typeof json === 'object');

  for (let i = 0; i < schema.length; i++) {
    const [name, type] = schema[i];
    rd[name] = readJSON(type, json[name]);
  }

  return rd;
}

function toJSON(rd, schema) {
  assert(rd);
  assert(schema);

  const json = {};

  for (let i = 0; i < schema.length; i++) {
    const [name, type] = schema[i];
    json[name] = writeJSON(type, rd[name]);
  }

  return json;
}

function readJSON(type, value) {
  switch (type) {
    case 'name': {
      assert(typeof value === 'string');
      assert(util.isName(value));
      return value;
    }
    case 'servers': {
      assert(Array.isArray(value));
      const names = [];
      for (const name of value) {
        assert(typeof name === 'string');
        assert(util.isName(name));
        names.push(name);
      }
      return names;
    }
    case 'inet4': {
      assert(typeof value === 'string');
      assert(IP.isIPv4String(value));
      return IP.normalize(value);
    }
    case 'inet6': {
      assert(typeof value === 'string');
      assert(IP.isIPv6String(value));
      let ip = IP.normalize(value);
      if (IP.isIPv4String(ip))
        ip = `::ffff:${ip}`;
      return ip;
    }
    case 'hex':
    case 'hex-end': {
      assert(typeof value === 'string');
      const data = Buffer.from(value, 'hex');
      assert(data.length === (value.length >>> 1));
      return data;
    }
    case 'base32': {
      assert(typeof value === 'string');
      return base32.decodeHex(value);
    }
    case 'base64':
    case 'base64-end': {
      assert(typeof value === 'string');
      assert(/^[A-Za-z0-9+\/=]+$/.test(value));
      return Buffer.from(value, 'base64');
    }
    case 'octet': {
      assert(typeof value === 'string');
      return value;
    }
    case 'string': {
      assert(typeof value === 'string');
      return value;
    }
    case 'txt': {
      assert(Array.isArray(value));

      const txt = [];

      for (const str of value) {
        assert(typeof str === 'string');
        txt.push(str);
      }

      return txt;
    }
    case 'nsec': {
      return encoding.toBitmap(value);
    }
    case 'tags': {
      assert(Array.isArray(value));

      const out = [];

      for (const tag of value) {
        assert((tag & 0xffff) === tag);
        out.push(tag);
      }

      return out;
    }
    case 'time': {
      return value;
    }
    case 'type': {
      return stringToType(value);
    }
    case 'u8': {
      assert((value & 0xff) === value);
      return value;
    }
    case 'u16': {
      assert((value & 0xffff) === value);
      return value;
    }
    case 'u32': {
      assert((value >>> 0) === value);
      return value;
    }
    case 'u48': {
      assert(Number.isSafeInteger(value));
      assert(value >= 0 && value <= 0xffffffffffff);
      return value;
    }
    case 'u64': {
      assert(typeof value === 'string');
      assert(value.length === 16);
      const data = Buffer.from(value, 'hex');
      assert(data.length === 8);
      return data;
    }
    default: {
      throw new Error('Unknown type.');
    }
  }
}

function writeJSON(type, value) {
  switch (type) {
    case 'name': {
      assert(typeof value === 'string');
      return value;
    }
    case 'servers': {
      assert(Array.isArray(value));
      return value;
    }
    case 'inet4': {
      assert(typeof value === 'string');
      return value;
    }
    case 'inet6': {
      assert(typeof value === 'string');
      return value;
    }
    case 'hex':
    case 'hex-end': {
      assert(Buffer.isBuffer(value));
      return value.toString('hex');
    }
    case 'base32': {
      assert(Buffer.isBuffer(value));
      return base32.encodeHex(value);
    }
    case 'base64':
    case 'base64-end': {
      assert(Buffer.isBuffer(value));
      return value.toString('base64');
    }
    case 'octet': {
      assert(typeof value === 'string');
      return value;
    }
    case 'string': {
      assert(typeof value === 'string');
      return value;
    }
    case 'txt': {
      assert(Array.isArray(value));
      return value;
    }
    case 'nsec': {
      assert(Buffer.isBuffer(value));
      return encoding.fromBitmap(value);
    }
    case 'tags': {
      assert(Array.isArray(value));
      return value;
    }
    case 'time': {
      assert(typeof value === 'number' && value >= 0);
      return value;
    }
    case 'type': {
      assert(typeof value === 'number');
      return typeToString(value);
    }
    case 'u8': {
      assert((value & 0xff) === value);
      return value;
    }
    case 'u16': {
      assert((value & 0xffff) === value);
      return value;
    }
    case 'u32': {
      assert((value >>> 0) === value);
      return value;
    }
    case 'u48': {
      assert(Number.isSafeInteger(value));
      assert(value >= 0 && value <= 0xffffffffffff);
      return value;
    }
    case 'u64': {
      assert(Buffer.isBuffer(value) && value.length === 8);
      return value.toString('hex');
    }
    default: {
      throw new Error('Unknown type.');
    }
  }
}

/*
 * Helpers
 */

function pad(num, len) {
  let str = num.toString(10);
  while (str.length < len)
    str = '0' + str;
  return str;
}

function unpad(str, start, end) {
  const num = str.substring(start, end);
  return util.parseU16(num);
}

function timeToString(t) {
  assert(Number.isSafeInteger(t) && t >= 0);

  const div = (t - util.now()) / YEAR68;

  let mod = Math.floor(div) - 1;

  if (mod < 0)
    mod = 0;

  const ti = t - (mod * YEAR68);

  const da = new Date();
  da.setTime(ti * 1000);

  const y = pad(da.getUTCFullYear(), 4);
  const m = pad(da.getUTCMonth() + 1, 2);
  const d = pad(da.getUTCDate(), 2);
  const hr = pad(da.getUTCHours(), 2);
  const mn = pad(da.getUTCMinutes(), 2);
  const sc = pad(da.getUTCSeconds(), 2);

  return `${y}${m}${d}${hr}${mn}${sc}`;
}

function stringToTime(s) {
  assert(typeof s === 'string');
  assert(s.length === 14);

  const y = unpad(s, 0, 4);
  const m = unpad(s, 4, 6);
  const d = unpad(s, 6, 8);
  const hr = unpad(s, 8, 10);
  const mn = unpad(s, 10, 12);
  const sc = unpad(s, 12, 14);

  const da = new Date();
  da.setUTCFullYear(y);
  da.setUTCMonth(m - 1);
  da.setUTCDate(d);
  da.setUTCHours(hr);
  da.setUTCMinutes(mn);
  da.setUTCSeconds(sc);

  const t = Math.floor(da.getTime() / 1000);
  const div = util.now() / YEAR68;

  let mod = Math.floor(div) - 1;

  if (mod < 0)
    mod = 0;

  return (t - (mod * YEAR68)) >>> 0;
}

/*
 * Expose
 */

exports.records = records;
exports.options = opts;
exports.fromString = fromString;
exports.toString = toString;
exports.fromJSON = fromJSON;
exports.toJSON = toJSON;
