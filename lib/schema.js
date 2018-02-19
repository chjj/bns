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
const util = require('./util');
const encoding = require('./encoding');
const {types, typesByVal, YEAR68, options} = require('./constants');
const {base32} = IP;

/*
 * Schemas
 */

const UNKNOWNSchema = [
  ['data', 'hex']
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
  ['bitmap', 'hex'] // ??
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
  ['nsap', 'hex'] // ??
];

const NSAPPTRSchema = PTRSchema;

const SIGSchema = [
  ['typeCovered', 'type'],
  ['algorithm', 'u8'],
  ['labels', 'u8'],
  ['origTTL', 'u32'],
  ['expiration', 'time'],
  ['inception', 'time'],
  ['keyTag', 'u16'],
  ['signerName', 'name'],
  ['signature', 'base64']
];

const KEYSchema = [
  ['flags', 'u16'],
  ['protocol', 'u8'],
  ['algorithm', 'u8'],
  ['publicKey', 'base64']
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
  ['typeBitmap', 'nsec3']
];

const EIDSchema = [
  ['endpoint', 'hex']
];

const NIMLOCSchema = [
  ['locator', 'hex']
];

const SRVSchema = [
  ['priority', 'u16'],
  ['weight', 'u16'],
  ['port', 'u16'],
  ['target', 'name']
];

const ATMASchema = [
  ['format', 'u8'],
  ['address', 'hex'] // ??
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
  ['certificate', 'base64']
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
  ['afd', 'hex'] // ??
];

const DSSchema = [
  ['keyTag', 'u16'],
  ['algorithm', 'u8'],
  ['digestType', 'u8'],
  ['digest', 'hex']
];

const SSHFPSchema = [
  ['algorithm', 'u8'],
  ['keyType', 'u8'],
  ['fingerprint', 'hex']
];

const IPSECKEYSchema = [
  ['precedence', 'u8'],
  ['gatewayType', 'u8'],
  ['algorithm', 'u8'],
  ['target', 'string'],
  ['publicKey', 'base64']
];

const RRSIGSchema = SIGSchema;

const NSECSchema = [
  ['nextDomain', 'name'],
  ['typeBitmap', 'nsec3']
];

const DNSKEYSchema = KEYSchema;

const DHCIDSchema = [
  ['digest', 'base64']
];

const NSEC3Schema = [
  ['hash', 'u8'],
  ['flags', 'u8'],
  ['iterations', 'u16'],
  ['salt', 'hex'],
  ['nextDomain', 'base32'],
  ['typeBitmap', 'nsec3']
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
  ['certificate', 'hex']
];

const SMIMEASchema = TLSASchema;

const HIPSchema = [
  ['algorithm', 'u8'],
  ['hit', 'hex'],
  ['publicKey', 'base64'],
  ['rendezvousServers', 'names']
];

const NINFOSchema = [
  ['zsData', 'stxt']
];

const RKEYSchema = KEYSchema;

const TALINKSchema = [
  ['prevName', 'name'],
  ['nextName', 'name']
];

const CDSSchema = DSSchema;

const CDNSKEYSchema = DNSKEYSchema;

const OPENPGPKEYSchema = [
  ['publicKey', 'base64']
];

const CSYNCSchema = [
  ['serial', 'u32'],
  ['flags', 'u16'],
  ['typeBitmap', 'nsec3']
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

const TKEYSchema = [
  ['algorithm', 'name'],
  ['inception', 'u32'], // time?
  ['expiration', 'u32'], // time?
  ['mode', 'u16'],
  ['error', 'u16'],
  ['key', 'hex'],
  ['other', 'hex']
];

const TSIGSchema = [
  ['algorithm', 'name'],
  ['timeSigned', 'u48'], // time?
  ['fudge', 'u16'], // time?
  ['mac', 'hex'],
  ['origID', 'u16'],
  ['error', 'u16'],
  ['other', 'hex']
];

const ANYSchema = UNKNOWNSchema;

const TASchema = [
  ['keyTag', 'u16'],
  ['algorithm', 'u8'],
  ['digestType', 'u8'],
  ['digest', 'hex']
];

const DLVSchema = DSSchema;

const NAMEPROOFSchema = [
  ['exists', 'bool'],
  ['nodes', 'nodes'],
  ['data', 'hex']
];

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
  ['nsid', 'hex']
];

const DAUSchema = [
  ['algCode', 'hex']
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
  ['cookie', 'hex']
];

const TCPKEEPALIVESchema = [
  ['length', 'u16'],
  ['timeout', 'u16']
];

const PADDINGSchema = [
  ['padding', 'hex']
];

const TRIEROOTSchema = [
  ['root', 'hex']
];

const LOCALSchema = [
  ['data', 'hex']
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
  [types.URI]: URISchema,
  [types.CAA]: CAASchema,
  [types.AVC]: AVCSchema,
  [types.TKEY]: TKEYSchema,
  [types.TSIG]: TSIGSchema,
  [types.IXFR]: null,
  [types.AXFR]: null,
  [types.MAILB]: null,
  [types.MAILA]: null,
  [types.ANY]: ANYSchema,
  [types.TA]: TASchema,
  [types.DLV]: DLVSchema,
  [types.NAMEPROOF]: NAMEPROOFSchema,
  [types.RESERVED]: null
};

/**
 * EDNS0 Option Classes By Value
 * @const {Object}
 */

const opts = {
  [options.UNKNOWN]: UNKNOWNSchema,
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
  [options.TRIEROOT]: TRIEROOTSchema,
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
      case 'base64':
      case 'names':
      case 'nsec3':
      case 'txt': {
        const left = parts.slice(i).join(' ');
        rd[name] = readType(type, left);
        i = len - 1;
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
    case 'names': {
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
      const data = Buffer.from(part, 'hex');
      assert(data.length === (part.length >>> 1));
      return data;
    }
    case 'base32': {
      return base32.decodeHex(part);
    }
    case 'base64': {
      const b64 = part.replace(/ +/, '');
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
    case 'nsec3': {
      const tns = part.split(' ');
      const ts = [];

      for (const tn of tns) {
        const t = types[tn];
        assert(t != null);
        ts.push(t);
      }

      return encoding.toBitmap(ts);
    }
    case 'time': {
      return stringToTime(part);
    }
    case 'type': {
      const type = types[part];
      assert(type != null);
      return type;
    }
    case 'u8': {
      const n = parseInt(part, 10);
      assert((n & 0xff) === n);
      return n;
    }
    case 'u16': {
      const n = parseInt(part, 10);
      assert((n & 0xffff) === n);
      return n;
    }
    case 'u32': {
      const n = parseInt(part, 10);
      assert((n >>> 0) === n);
      return n;
    }
    case 'u48': {
      const n = parseInt(part, 10);
      assert(n >= 0 && n <= 0xffffffffffff);
      return n;
    }
    case 'u64': {
      let hi = 0;
      let lo = 0;

      for (; i < part.length; i++) {
        let ch = part.charCodeAt(i);

        if (ch < 0x30 || ch > 0x39)
          throw new Error('Invalid string (parse error).');

        ch -= 0x30;

        lo *= 10;
        lo += ch;

        hi *= 10;

        if (lo > 0xffffffff) {
          ch = lo % 0x100000000;
          hi += (lo - ch) / 0x100000000;
          lo = ch;
        }

        if (hi > 0xffffffff)
          throw new Error('Invalid string (overflow).');
      }

      const out = Buffer.allocUnsafe(8);
      out.writeUInt32BE(hi, true);
      out.writeUInt32BE(lo, true);
      return out;
    }
    case 'bool': {
      assert(part === '0' || part === '1');
      return part === '1';
    }
    case 'nodes': {
      const parts = part.split(':');
      const nodes = [];

      for (const part of parts) {
        const data = Buffer.from(part, 'hex');
        assert(data.length === (part.length >>> 1));
        nodes.push(data);
      }

      return nodes;
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
    case 'names': {
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
      return value.toString('hex');
    }
    case 'base32': {
      assert(Buffer.isBuffer(value));
      return base32.encodeHex(value);
    }
    case 'base64': {
      assert(Buffer.isBuffer(value));
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
    case 'nsec3': {
      assert(Buffer.isBuffer(value));

      const ts = encoding.fromBitmap(value);
      const tns = [];

      for (const t of ts) {
        const tn = typesByVal[t];
        if (tn != null)
          tns.push(tn);
      }

      return tns.join(' ');
    }
    case 'time': {
      assert(typeof value === 'number');
      return timeToString(value);
    }
    case 'type': {
      assert(typeof value === 'number');
      return typesByVal[value] || 'UNKNOWN';
    }
    case 'u8': {
      assert(typeof value === 'number');
      return value.toString(10);
    }
    case 'u16': {
      assert(typeof value === 'number');
      return value.toString(10);
    }
    case 'u32': {
      assert(typeof value === 'number');
      return value.toString(10);
    }
    case 'u48': {
      assert(typeof value === 'number');
      return value.toString(10);
    }
    case 'u64': {
      assert(Buffer.isBuffer(value) && value.length === 8);

      let hi = value.readUInt32BE(0, true);
      let lo = value.readUInt32BE(4, true);
      let str = '';

      do {
        const mhi = hi % 10;
        hi -= mhi;
        hi /= 10;
        lo += mhi * 0x100000000;

        const mlo = lo % 10;
        lo -= mlo;
        lo /= 10;

        let ch = mlo;

        ch += 0x30;

        str = String.fromCharCode(ch) + str;
      } while (lo > 0 || hi > 0);

      return str;
    }
    case 'bool': {
      assert(typeof value === 'boolean');
      return value ? '1' : '0';
    }
    case 'nodes': {
      const out = [];
      for (const node of value)
        out.push(node.toString('hex'));
      return out.join(':');
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
    case 'names': {
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
      const ip = IP.normalize(value);
      if (IP.isIPv4String(ip))
        ip = `::ffff:${ip}`;
      return ip;
    }
    case 'hex': {
      assert(typeof value === 'string');
      const data = Buffer.from(value, 'hex');
      assert(data.length === (value.length >>> 1));
      return data;
    }
    case 'base32': {
      assert(typeof value === 'string');
      return base32.decodeHex(value);
    }
    case 'base64': {
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
    case 'nsec3': {
      return encoding.toBitmap(value);
    }
    case 'time': {
      return value;
    }
    case 'type': {
      const type = types[value];
      assert(type != null);
      return type;
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
      assert(value >= 0 && value <= 0xffffffffffff);
      assert((value % 1) === 0);
      return value;
    }
    case 'u64': {
      assert(typeof value === 'string');
      assert(value.length === 16);
      const data = Buffer.from(value, 'hex');
      assert(data.length === 8);
      return data;
    }
    case 'bool': {
      assert(typeof value === 'boolean');
      return value;
    }
    case 'nodes': {
      assert(Array.isArray(value));
      const nodes = [];
      for (const item of value) {
        assert(typeof item === 'string');
        const data = Buffer.from(item, 'hex');
        assert(data.length === (item.length >>> 1));
        nodes.push(data);
      }
      return nodes;
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
    case 'names': {
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
    case 'hex': {
      assert(Buffer.isBuffer(value));
      return value.toString('hex');
    }
    case 'base32': {
      assert(Buffer.isBuffer(value));
      return base32.encodeHex(value);
    }
    case 'base64': {
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
    case 'nsec3': {
      assert(Buffer.isBuffer(value));
      return encoding.fromBitmap(value);
    }
    case 'time': {
      assert(typeof value === 'number' && value >= 0);
      return value;
    }
    case 'type': {
      assert(typeof value === 'number');
      return typesByVal[value] || 'UNKNOWN';
    }
    case 'u8': {
      assert(typeof value === 'number');
      return value;
    }
    case 'u16': {
      assert(typeof value === 'number');
      return value;
    }
    case 'u32': {
      assert(typeof value === 'number');
      return value;
    }
    case 'u48': {
      assert(typeof value === 'number');
      return value;
    }
    case 'u64': {
      assert(Buffer.isBuffer(value) && value.length === 8);
      return value.toString('hex');
    }
    case 'bool': {
      assert(typeof value === 'boolean');
      return value;
    }
    case 'nodes': {
      assert(Array.isArray(value));

      const json = [];

      for (const node of value)
        json.push(node.toString('hex'));

      return json;
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
  const s = str.substring(start, end);
  assert(/^\d+$/.test(s));
  return parseInt(s, 10);
}

function timeToString(t) {
  assert(typeof t === 'number' && isFinite(t) && t >= 0);

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
