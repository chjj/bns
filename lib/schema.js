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
  stringToType
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
  ['cpu', 'char'],
  ['os', 'char']
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
  ['psdnAddress', 'octet'] // technically character-string
];

const ISDNSchema = [
  ['address', 'octet'], // technically character-string
  ['sa', 'octet'] // technically character-string
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
  ['longitude', 'octet'], // unspec
  ['latitude', 'octet'], // unspec
  ['altitude', 'octet'] // unspec
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
  ['flags', 'char'],
  ['service', 'char'],
  ['regexp', 'char'],
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
  ['prefixLen', 'u8'],
  ['address', 'u16'],
  ['prefix', 'name']
];

const DNAMESchema = CNAMESchema;

const OPTSchema = UNKNOWNSchema;

const APLSchema = [
  ['items', 'apl']
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
  ['target', 'target'],
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
  ['salt', 'hex-end']
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
  ['uinfo', 'char'] // unspec?
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
  ['nodeID', 'nid64']
];

const L32Schema = [
  ['preference', 'u16'],
  ['locator32', 'nid32']
];

const L64Schema = [
  ['preference', 'u16'],
  ['locator64', 'nid64']
];

const LPSchema = [
  ['preference', 'u16'],
  ['fqdn', 'name']
];

const EUI48Schema = [
  ['address', 'eui48']
];

const EUI64Schema = [
  ['address', 'eui64']
];

const TKEYSchema = [
  ['algorithm', 'name'],
  ['inception', 'u32'],
  ['expiration', 'u32'],
  ['mode', 'u16'],
  ['error', 'u16'],
  ['key', 'hex'],
  ['other', 'hex-end']
];

const TSIGSchema = [
  ['algorithm', 'name'],
  ['timeSigned', 'u48'],
  ['fudge', 'u16'],
  ['mac', 'hex'],
  ['origID', 'u16'],
  ['error', 'u16'],
  ['other', 'hex-end']
];

const URISchema = [
  ['priority', 'u16'],
  ['weight', 'u16'],
  ['target', 'octet']
];

const CAASchema = [
  ['flag', 'u8'],
  ['tag', 'octet'],
  ['value', 'char']
];

const AVCSchema = TXTSchema;

const DOASchema = [
  ['enterprise', 'u32'],
  ['type', 'u32'],
  ['location', 'u8'],
  ['mediaType', 'char'],
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
  ['address', 'inet']
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
  assert(rd && typeof rd === 'object');
  assert(Array.isArray(schema));
  assert(typeof str === 'string');

  const STATE_SKIP = 0;
  const STATE_SEEK = 1;
  const STATE_TOEND = 2;
  const STATE_CHAR = 3;

  let index = 0;
  let start = -1;
  let end = -1;
  let state = STATE_SKIP;
  let i = 0;

  const parts = [];

  // First, split the string into
  // parts based on the schema.
outer:
  for (; i < str.length; i++) {
    const ch = str[i];

    switch (state) {
      case STATE_SKIP: {
        switch (ch) {
          case ' ':
          case '\t':
          case '\r':
          case '\n': {
            break;
          }

          case ';': {
            break outer;
          }

          default: {
            assert(start === -1);
            assert(end === -1);

            if (index === schema.length)
              throw new Error('Too many fields for record.');

            const [, type] = schema[index];

            index += 1;
            start = i;
            end = i + 1;

            switch (type) {
              case 'hex-end':
              case 'base64-end':
              case 'servers':
              case 'nsec':
              case 'txt':
              case 'tags':
              case 'apl': {
                state = STATE_TOEND;
                break;
              }

              case 'char': {
                if (ch !== '"')
                  throw new Error(`Expected '"', but saw: '${ch}'.`);

                state = STATE_CHAR;

                break;
              }

              default: {
                state = STATE_SEEK;
                break;
              }
            }
          }
        }

        break;
      }

      case STATE_SEEK: {
        switch (ch) {
          case ' ':
          case '\t':
          case '\r':
          case '\n': {
            assert(start !== -1);
            assert(end === i);

            const part = str.substring(start, end);
            parts.push(part);

            start = -1;
            end = -1;
            state = STATE_SKIP;

            break;
          }

          case ';': {
            break outer;
          }

          default: {
            end = i + 1;
            break;
          }
        }

        break;
      }

      case STATE_TOEND: {
        switch (ch) {
          case ' ':
          case '\t':
          case '\r':
          case '\n': {
            break;
          }

          case ';': {
            break outer;
          }

          default: {
            end = i + 1;
            break;
          }
        }

        break;
      }

      case STATE_CHAR: {
        switch (ch) {
          case ' ':
          case '\t':
          case '\r':
          case '\n': {
            end = i + 1;
            break;
          }

          case '\\': {
            i += 1;

            if (isDigits(str, i))
              i += 2;

            end = i + 1;

            break;
          }

          case '"': {
            assert(start !== -1);
            assert(end === i);

            const part = str.substring(start, end + 1);
            parts.push(part);

            start = -1;
            end = -1;
            state = STATE_SKIP;

            break;
          }

          default: {
            end = i + 1;
            break;
          }
        }

        break;
      }
    }
  }

  if (state === STATE_CHAR)
    throw new Error('Unclosed double quote.');

  if (index !== schema.length)
    throw new Error('Missing data for record.');

  if (start !== -1) {
    assert(end !== -1);

    const part = str.substring(start, end);
    parts.push(part);
  }

  assert(parts.length === schema.length);

  // Then, parse according to schema.
  for (let i = 0; i < parts.length; i++) {
    const part = parts[i];
    const [name, type] = schema[i];

    rd[name] = readType(type, part, rd);
  }

  return rd;
}

function toString(rd, schema) {
  assert(rd && typeof rd === 'object');
  assert(Array.isArray(schema));

  const str = [];

  for (let i = 0; i < schema.length; i++) {
    const [name, type] = schema[i];
    const value = rd[name];
    str.push(writeType(type, value));
  }

  return str.join(' ');
}

function readType(type, str, rd) {
  assert(typeof type === 'string');
  assert(typeof str === 'string');

  switch (type) {
    case 'name': {
      assert(encoding.isName(str));
      return str;
    }

    case 'servers': {
      const names = util.splitSP(str);

      for (const name of names)
        assert(encoding.isName(name));

      return names;
    }

    case 'inet4': {
      const ip = IP.toBuffer(str);

      assert(IP.isIPv4(ip));

      return IP.toString(ip);
    }

    case 'inet6': {
      const ip = IP.toBuffer(str);

      if (IP.isIPv4(ip))
        return `::ffff:${IP.toString(ip)}`;

      return IP.toString(ip);
    }

    case 'inet': {
      return IP.normalize(str);
    }

    case 'target': {
      return parseTarget(str);
    }

    case 'hex': {
      if (str === '-')
        return DUMMY;

      return util.parseHex(str);
    }

    case 'hex-end': {
      if (str === '-')
        return DUMMY;

      const hex = util.stripSP(str);

      return util.parseHex(hex);
    }

    case 'base32': {
      if (str === '-')
        return DUMMY;

      return base32.decodeHex(str);
    }

    case 'base64': {
      if (str === '-')
        return DUMMY;

      return util.parseB64(str);
    }

    case 'base64-end': {
      if (str === '-')
        return DUMMY;

      const b64 = util.stripSP(str);

      return util.parseB64(b64);
    }

    case 'char': {
      return unquote(str);
    }

    case 'octet': {
      assert(encoding.isString(str, true));
      return str;
    }

    case 'txt': {
      const txts = [];

      let last = -1;

      for (let i = 0; i < str.length; i++) {
        const ch = str[i];

        if (ch === '\\') {
          i += 1;
          if (isDigits(str, i))
            i += 2;
          continue;
        }

        if (ch === '"') {
          if (last === -1) {
            last = i;
            continue;
          }

          const txt = str.substring(last, i + 1);

          txts.push(unquote(txt));
          last = -1;
        }
      }

      if (last !== -1)
        throw new Error('Unclosed double quote.');

      return txts;
    }

    case 'nsec': {
      const parts = util.splitSP(str);
      const types = [];

      for (const part of parts)
        types.push(stringToType(part));

      return encoding.toBitmap(types);
    }

    case 'tags': {
      const parts = util.splitSP(str);
      const tags = [];

      for (const part of parts)
        tags.push(util.parseU16(part));

      return tags;
    }

    case 'time': {
      return parseTime(str);
    }

    case 'type': {
      return stringToType(str);
    }

    case 'u8': {
      return util.parseU8(str);
    }

    case 'u16': {
      return util.parseU16(str);
    }

    case 'u32': {
      return util.parseU32(str);
    }

    case 'u48': {
      return util.parseU48(str);
    }

    case 'u64': {
      const [hi, lo] = util.parseU64(str);
      const buf = Buffer.allocUnsafe(8);
      buf.writeUInt32BE(hi, true);
      buf.writeUInt32BE(lo, true);
      return buf;
    }

    case 'nid32': {
      return parseNID32(str);
    }

    case 'nid64': {
      return parseNID64(str);
    }

    case 'eui48': {
      return parseEUI(str, 6);
    }

    case 'eui64': {
      return parseEUI(str, 8);
    }

    case 'apl': {
      const {AP} = rd;
      const parts = util.splitSP(str);
      const items = [];

      for (const part of parts)
        items.push(AP.fromString(part));

      return items;
    }

    default: {
      throw new Error('Unknown type.');
    }
  }
}

function writeType(type, value) {
  assert(typeof type === 'string');

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

    case 'inet': {
      assert(typeof value === 'string');
      return value;
    }

    case 'target': {
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
      const chunks = [];

      for (let i = 0; i < hex.length; i += 56)
        chunks.push(hex.substring(i, i + 56));

      return chunks.join(' ');
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
      const chunks = [];

      for (let i = 0; i < b64.length; i += 56)
        chunks.push(b64.substring(i, i + 56));

      return chunks.join(' ');
    }

    case 'char': {
      assert(typeof value === 'string');
      return quote(value);
    }

    case 'octet': {
      assert(typeof value === 'string');
      return value;
    }

    case 'txt': {
      assert(Array.isArray(value));

      const chunks = [];

      for (const str of value)
        chunks.push(quote(str));

      return chunks.join(' ');
    }

    case 'nsec': {
      assert(Buffer.isBuffer(value));

      const types = encoding.fromBitmap(value);
      const parts = [];

      for (const type of types)
        parts.push(typeToString(type));

      return parts.join(' ');
    }

    case 'tags': {
      assert(Array.isArray(value));
      return value.join(' ');
    }

    case 'time': {
      return serializeTime(value);
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

    case 'nid32': {
      return serializeNID32(value);
    }

    case 'nid64': {
      return serializeNID64(value);
    }

    case 'eui48': {
      return serializeEUI(value, 6);
    }

    case 'eui64': {
      return serializeEUI(value, 8);
    }

    case 'apl': {
      assert(Array.isArray(value));

      const out = [];

      for (const ap of value)
        out.push(ap.toString());

      return out.join(' ');
    }

    default: {
      throw new Error('Unknown type.');
    }
  }
}

function fromJSON(rd, schema, json) {
  assert(rd && typeof rd === 'object');
  assert(Array.isArray(schema));
  assert(json && typeof json === 'object');

  for (let i = 0; i < schema.length; i++) {
    const [name, type] = schema[i];
    rd[name] = readJSON(type, json[name], rd);
  }

  return rd;
}

function toJSON(rd, schema) {
  assert(rd && typeof rd === 'object');
  assert(Array.isArray(schema));

  const json = {};

  for (let i = 0; i < schema.length; i++) {
    const [name, type] = schema[i];
    json[name] = writeJSON(type, rd[name]);
  }

  return json;
}

function readJSON(type, value, rd) {
  assert(typeof type === 'string');

  switch (type) {
    case 'name': {
      assert(encoding.isName(value));
      return value;
    }

    case 'servers': {
      assert(Array.isArray(value));

      const names = [];

      for (const name of value) {
        assert(encoding.isName(name));
        names.push(name);
      }

      return names;
    }

    case 'inet4': {
      const ip = IP.toBuffer(value);

      assert(IP.isIPv4(ip));

      return IP.toString(ip);
    }

    case 'inet6': {
      const ip = IP.toBuffer(value);

      if (IP.isIPv4(ip))
        return `::ffff:${IP.toString(ip)}`;

      return IP.toString(ip);
    }

    case 'inet': {
      return IP.normalize(value);
    }

    case 'target': {
      return parseTarget(value);
    }

    case 'hex':
    case 'hex-end': {
      return util.parseHex(value);
    }

    case 'base32': {
      return base32.decodeHex(value);
    }

    case 'base64':
    case 'base64-end': {
      return util.parseB64(value);
    }

    case 'char': {
      assert(encoding.isString(value, false));
      return value;
    }

    case 'octet': {
      assert(encoding.isString(value, true));
      return value;
    }

    case 'txt': {
      assert(Array.isArray(value));

      const txt = [];

      for (const str of value) {
        assert(encoding.isString(str, false));
        txt.push(str);
      }

      return txt;
    }

    case 'nsec': {
      return encoding.toBitmap(value);
    }

    case 'tags': {
      assert(Array.isArray(value));

      const tags = [];

      for (const tag of value) {
        assert((tag & 0xffff) === tag);
        tags.push(tag);
      }

      return tags;
    }

    case 'time': {
      assert(Number.isSafeInteger(value));
      assert(value >= 0 && value <= 0xffffffffffff);
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

    case 'nid32': {
      return parseNID32(value);
    }

    case 'nid64': {
      return parseNID64(value);
    }

    case 'eui48': {
      return parseEUI(value, 6);
    }

    case 'eui64': {
      return parseEUI(value, 8);
    }

    case 'apl': {
      assert(Array.isArray(value));

      const {AP} = rd;
      const out = [];

      for (const item of value)
        out.push(AP.fromJSON(item));

      return out;
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

    case 'inet': {
      assert(typeof value === 'string');
      return value;
    }

    case 'target': {
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

    case 'char': {
      assert(typeof value === 'string');
      return value;
    }

    case 'octet': {
      assert(typeof value === 'string');
      return value;
    }

    case 'txt': {
      assert(Array.isArray(value));
      return value;
    }

    case 'nsec': {
      return encoding.fromBitmap(value);
    }

    case 'tags': {
      assert(Array.isArray(value));
      return value;
    }

    case 'time': {
      assert(Number.isSafeInteger(value));
      assert(value >= 0 && value <= 0xffffffffffff);
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

    case 'nid32': {
      return serializeNID32(value);
    }

    case 'nid64': {
      return serializeNID64(value);
    }

    case 'eui48': {
      return serializeEUI(value, 6);
    }

    case 'eui64': {
      return serializeEUI(value, 8);
    }

    case 'apl': {
      assert(Array.isArray(value));

      const out = [];

      for (const ap of value)
        out.push(ap.toJSON());

      return out;
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

function serializeTime(t) {
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

function parseTime(s) {
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

function unquote(str) {
  assert(typeof str === 'string');
  assert(str.length >= 2);
  assert(str[0] === '"');
  assert(str[str.length - 1] === '"');

  const txt = str.slice(1, -1);

  assert(encoding.isString(txt, false));

  return txt;
}

function quote(str) {
  assert(typeof str === 'string');
  return `"${str}"`;
}

function isDigits(str, off) {
  if (off + 3 > str.length)
    return false;

  const a = str.charCodeAt(off + 0);

  if (a < 0x30 || a > 0x39)
    return false;

  const b = str.charCodeAt(off + 1);

  if (b < 0x30 || b > 0x39)
    return false;

  const c = str.charCodeAt(off + 2);

  if (c < 0x30 || c > 0x39)
    return false;

  return true;
}

function parseTarget(str) {
  assert(typeof str === 'string');

  try {
    return IP.normalize(str);
  } catch (e) {
    ;
  }

  if (!encoding.isName(str))
    throw new Error('Invalid target.');

  return str;
}

function parseNID32(str) {
  assert(typeof str === 'string');

  const data = IP.toBuffer(str);

  if (!IP.isIPv4(data))
    throw new Error('Invalid NID32.');

  return data.slice(12, 16);
}

function serializeNID32(data) {
  assert(Buffer.isBuffer(data));

  if (data.length !== 4)
    throw new Error('Invalid NID32.');

  return IP.toString(data);
}

function parseNID64(str) {
  assert(typeof str === 'string');

  if (str.indexOf('::') === -1) {
    if (str.length === 0
        || str[str.length - 1] !== ':') {
      str += ':';
    }
    str += ':';
  }

  const data = IP.toBuffer(str);

  return data.slice(0, 8);
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

function parseEUI(str, size) {
  assert(typeof str === 'string');
  assert(size === 6 || size === 8);

  if (str.length !== (size * 2) + (size - 1))
    throw new Error('Invalid EUI.');

  if (str[0] === '-' || str[str.length - 1] === '-')
    throw new Error('Invalid EUI.');

  if (str.indexOf('--') !== -1)
    throw new Error('Invalid EUI.');

  str = str.replace(/-/g, '');

  if (str.length !== size * 2)
    throw new Error('Invalid EUI.');

  return util.parseHex(str);
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

/*
 * Expose
 */

exports.records = records;
exports.options = opts;
exports.fromString = fromString;
exports.toString = toString;
exports.fromJSON = fromJSON;
exports.toJSON = toJSON;
