/*!
 * wire.js - wire types for bns
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
const bio = require('bufio');
const IP = require('binet');
const encoding = require('./encoding');
const util = require('./util');

const {
  sizeName,
  writeNameBW,
  readNameBR,
  toBitmap,
  fromBitmap,
  hasType
} = encoding;

/*
 * Constants
 */

const DUMMY = Buffer.alloc(0);
const DUMMY6 = Buffer.alloc(6);
const DUMMY8 = Buffer.alloc(8);

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
  UPDATE: 5
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
  NAMEERROR: 3, // Non-Existent Domain
  NOTIMPLEMENTED: 4, // Not Implemented
  REFUSED: 5, // Query Refused
  YXDOMAIN: 6, // Name Exists when it should not
  YXRRSET: 7, // RR Set Exists when it should not
  NXRRSET: 8, // RR Set that should exist does not
  NOTAUTH: 9, // Server Not Authoritative for zone
  NOTZONE: 10, // Name not contained in zone
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
 * Record Types (rrtypes)
 * @enum {Number}
 * @default
 */

const types = {
  NONE: 0,
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
  NB: 32, // obsolete
  NIMLOC: 32, // not-in-use
  NBSTAT: 33, // obsolete
  SRV: 33,
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
  RESERVED: 65535 // unimpl
};

/**
 * Question and Record Classes (qclass/rclass)
 * @enum {Number}
 * @default
 */

const classes = {
  INET: 1,
  CSNET: 2,
  CHAOS: 3,
  HESIOD: 4,
  NONE: 254,
  ANY: 255
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
 * EDNS0 Option Codes
 * @enum {Number}
 * @default
 */

const options = {
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
  LOCALSTART: 65001, // Beginning of range reserved for local/experimental use
  LOCALEND: 65534 // End of range reserved for local/experimental use
};

/**
 * Message
 */

class Message {
  constructor() {
    this.id = 0;
    this.qr = false;
    this.opcode = opcodes.QUERY;
    this.aa = false;
    this.tc = false;
    this.rd = false;
    this.ra = false;
    this.z = false;
    this.ad = false;
    this.cd = false;
    this.code = codes.NOERROR; // rcode
    this.question = [];
    this.answer = [];
    this.authority = [];
    this.additional = [];
  }

  inject(msg) {
    this.id = msg.id;
    this.qr = msg.qr;
    this.opcode = msg.opcode;
    this.aa = msg.aa;
    this.tc = msg.tc;
    this.rd = msg.rd;
    this.ra = msg.ra;
    this.z = msg.z;
    this.ad = msg.ad;
    this.cd = msg.cd;
    this.code = msg.code;
    this.question = msg.question;
    this.answer = msg.answer;
    this.authority = msg.authority;
    this.additional = msg.additional;
    return this;
  }

  clone() {
    const msg = new this.constructor();
    return msg.inject(this);
  }

  respond(req) {
    this.id = req.id;
    this.opcode = req.opcode;
    this.qr = true;
    this.rd = req.rd;
    this.cd = req.cd;

    this.question = [];

    for (const qs of req.question)
      this.question.push(qs);

    const opt = req.getEDNS0();

    if (opt)
      this.setEDNS0(opt.usize, opt.dok);

    return this;
  }

  ednsIndex() {
    for (let i = 0; i < this.additional.length; i++) {
      const rr = this.additional[i];
      if (rr.isEDNS0())
        return i;
    }
    return -1;
  }

  getEDNS0() {
    const index = this.ednsIndex();

    if (index === -1)
      return null;

    return this.additional[index];
  }

  isEDNS0() {
    return this.ednsIndex() !== -1;
  }

  ensureEDNS0() {
    const opt = this.getEDNS0();

    if (opt)
      return opt;

    const rr = new Record();

    rr.name = '.';
    rr.type = types.OPT;
    rr.version = 0;
    rr.ecode = 0;
    rr.usize = 512;
    rr.dok = false;
    rr.data = new OPTRecord();

    this.additional.push(rr);

    return rr;
  }

  setEDNS0(usize, dok) {
    const opt = this.ensureEDNS0();
    opt.usize = usize;
    opt.dok = dok;
    return this;
  }

  unsetEDNS0() {
    const index = this.ednsIndex();

    if (index === -1)
      return this;

    this.additional.splice(index, 1);

    return this;
  }

  isDNSSEC() {
    const opt = this.getEDNS0();

    if (!opt)
      return false;

    return opt.dok;
  }

  minTTL() {
    const {answer, authority, additional} = this;
    const sections = [answer, authority, additional];

    let ttl = -1;

    for (const section of sections) {
      for (const rr of section) {
        if (rr.type === types.OPT) {
          const ettl = rr.ttl & 0xffff;

          if (ettl === 0)
            continue;

          if (ttl === -1 || ettl < ttl)
            ttl = ettl;

          continue;
        }

        if (ttl === -1 || rr.ttl < ttl)
          ttl = rr.ttl;

        if (rr.type === types.RRSIG) {
          const e = rr.data.expiration;
          const n = util.now();
          const t = e - n;

          if (t > 0 && t < ttl)
            ttl = t;
        }
      }
    }

    if (ttl === -1)
      ttl = 0;

    return ttl;
  }

  getSizes(udp) {
    let max = 512;

    if (udp) {
      const opt = this.getEDNS0();
      if (opt)
        max = opt.usize;
    }

    let size = 12;
    let items = 0;

    for (const qs of this.question)
      size += qs.getSize();

    assert(size <= max);

    for (const rr of this.answer) {
      const sz = rr.getSize();
      if (udp && size + sz > max)
        return [size, items];
      size += sz;
      items += 1;
    }

    for (const rr of this.authority) {
      const sz = rr.getSize();
      if (udp && size + sz > max)
        return [size, items];
      size += sz;
      items += 1;
    }

    const osize = size;
    const oitems = items;

    for (const rr of this.additional) {
      const sz = rr.getSize();
      if (udp && size + sz > max)
        return [osize, oitems];
      size += sz;
      items += 1;
    }

    if (!udp)
      items = -1;

    return [size, items];
  }

  getSize() {
    const [size] = this.getSizes(false);
    return size;
  }

  toWriter(bw, items) {
    if (items == null)
      items = -1;

    const body = this.answer.length + this.authority.length;

    if (items === -1)
      items = body + this.additional.length;

    bw.writeU16BE(this.id);

    let bits = 0;

    if (this.qr)
      bits |= flags.QR;

    if (this.opcode)
      bits |= (this.opcode & 0x0f) << 11;

    if (this.aa)
      bits |= flags.AA;

    if (this.tc || items < body)
      bits |= flags.TC;

    if (this.rd)
      bits |= flags.RD;

    if (this.ra)
      bits |= flags.RA;

    if (this.z)
      bits |= flags.Z;

    if (this.ad)
      bits |= flags.AD;

    if (this.cd)
      bits |= flags.CD;

    if (this.code)
      bits |= this.code & 0x0f;

    bw.writeU16BE(bits);
    bw.writeU16BE(this.question.length);
    bw.writeU16BE(this.answer.length);
    bw.writeU16BE(this.authority.length);
    bw.writeU16BE(this.additional.length);

    for (const qs of this.question)
      qs.toWriter(bw);

    for (const rr of this.answer) {
      rr.toWriter(bw);
      if (--items === 0)
        return bw;
    }

    for (const rr of this.authority) {
      rr.toWriter(bw);
      if (--items === 0)
        return bw;
    }

    for (const rr of this.additional) {
      rr.toWriter(bw);
      if (--items === 0)
        return bw;
    }

    return bw;
  }

  toRaw(udp) {
    if (udp == null)
      udp = false;

    const [size, items] = this.getSizes(udp);
    const bw = bio.write(size);

    this.toWriter(bw, items);

    return bw.render();
  }

  fromReader(br) {
    const id = br.readU16BE();
    const bits = br.readU16BE();
    const qdcount = br.readU16BE();
    const ancount = br.readU16BE();
    const nscount = br.readU16BE();
    const arcount = br.readU16BE();

    this.id = id;
    this.qr = (bits & flags.QR) !== 0;
    this.opcode = (bits >>> 11) & 0x0f;
    this.aa = (bits & flags.AA) !== 0;
    this.tc = (bits & flags.TC) !== 0;
    this.rd = (bits & flags.RD) !== 0;
    this.ra = (bits & flags.RA) !== 0;
    this.z = (bits & flags.Z) !== 0;
    this.ad = (bits & flags.AD) !== 0;
    this.cd = (bits & flags.CD) !== 0;
    this.code = bits & 0x0f;

    for (let i = 0; i < qdcount; i++) {
      if (br.left() === 0)
        return this;
      const qs = Question.fromReader(br);
      this.question.push(qs);
    }

    for (let i = 0; i < ancount; i++) {
      if (this.tc) {
        if (br.left() === 0)
          return this;
      }
      const rr = Record.fromReader(br);
      this.answer.push(rr);
    }

    for (let i = 0; i < nscount; i++) {
      if (this.tc) {
        if (br.left() === 0)
          return this;
      }
      const rr = Record.fromReader(br);
      this.authority.push(rr);
    }

    for (let i = 0; i < arcount; i++) {
      if (br.left() === 0)
        return this;
      const rr = Record.fromReader(br);
      this.additional.push(rr);
    }

    return this;
  }

  fromRaw(data) {
    return this.fromReader(bio.read(data));
  }

  static fromReader(br) {
    return new this().fromReader(br);
  }

  static fromRaw(data) {
    return new this().fromRaw(data);
  }
}

/**
 * Question
 */

class Question {
  constructor(name, type) {
    if (name == null)
      name = '';

    if (type == null)
      type = types.ANY;

    if (typeof type === 'string') {
      type = type.toUpperCase();
      assert(types[type] != null, 'Unknown type.');
      type = types[type];
    }

    assert(typeof name === 'string');
    assert(typeof type === 'number');

    if (name.length === 0 || name[name.length - 1] !== '.')
      name += '.';

    this.name = name;
    this.type = type; // qtype
    this.class = classes.INET; // qclass
  }

  equals(qs) {
    assert(qs instanceof Question);
    return util.equal(this.name, qs.name)
      && this.type === qs.type
      && this.class === qs.class;
  }

  inject(qs) {
    this.name = qs.name;
    this.type = qs.type;
    this.class = qs.class;
    return this;
  }

  clone() {
    const qs = new this.constructor();
    return qs.inject(this);
  }

  getSize() {
    return sizeName(this.name) + 4;
  }

  toWriter(bw) {
    writeNameBW(bw, this.name);
    bw.writeU16BE(this.type);
    bw.writeU16BE(this.class);
    return bw;
  }

  toRaw() {
    const size = this.getSize();
    const bw = bio.write(size);
    this.toWriter(bw);
    return bw.render();
  }

  fromReader(br) {
    this.name = readNameBR(br);

    if (br.left() === 0)
      return this;

    this.type = br.readU16BE();

    if (br.left() === 0)
      return this;

    this.class = br.readU16BE();

    return this;
  }

  fromRaw(data) {
    return this.fromReader(bio.read(data));
  }

  static fromReader(br) {
    return new this().fromReader(br);
  }

  static fromRaw(data) {
    return new this().fromRaw(data);
  }
}

/**
 * Record
 */

class Record {
  constructor() {
    this.name = '.';
    this.type = types.NONE; // rrtype
    this.class = classes.INET;
    this.ttl = 0;
    this.data = new UNKNOWNRecord(); // rdata
  }

  inject(r) {
    this.name = r.name;
    this.type = r.type;
    this.class = r.class;
    this.ttl = r.ttl;
    this.data = r.data;
    return this;
  }

  clone() {
    const r = new this.constructor();
    return r.inject(this);
  }

  isEDNS0() {
    return this.type === types.OPT;
  }

  get ettl() {
    return this.ttl & 0xffff;
  }

  set ettl(v) {
    this.ttl &= ~0xffff;
    this.ttl |= v & 0xffff;
    this.ttl >>>= 0;
  }

  get version() {
    return (this.ttl >>> 16) & 0xff;
  }

  set version(v) {
    this.ttl &= ~(0xff << 16);
    this.ttl |= (v & 0xff) << 16;
    this.ttl >>>= 0;
  }

  get ecode() {
    return (this.ttl >>> 24) & 0xff;
  }

  set ecode(v) {
    this.ttl &= ~(0xff << 24);
    this.ttl |= (v & 0xff) << 24;
    this.ttl >>>= 0;
  }

  get usize() {
    return this.class;
  }

  set usize(v) {
    this.class = v;
  }

  get dok() {
    return (this.ttl & eflags.DO) !== 0;
  }

  set dok(v) {
    if (!v)
      this.ttl &= ~eflags.DO;
    else
      this.ttl |= eflags.DO;
  }

  getSize() {
    return sizeName(this.name) + 10 + this.data.getSize();
  }

  toWriter(bw) {
    writeNameBW(bw, this.name);
    bw.writeU16BE(this.type);
    bw.writeU16BE(this.class);
    bw.writeU32BE(this.ttl);
    bw.writeU16BE(this.data.getSize());
    this.data.toWriter(bw);
    return bw;
  }

  toRaw() {
    const size = this.getSize();
    const bw = bio.write(size);
    this.toWriter(bw);
    return bw.render();
  }

  fromReader(br) {
    this.name = readNameBR(br);
    this.type = br.readU16BE();
    this.class = br.readU16BE();
    this.ttl = br.readU32BE();
    this.data = read(this.type, br);
    return this;
  }

  fromRaw(data) {
    return this.fromReader(bio.read(data));
  }

  static fromReader(br) {
    return new this().fromReader(br);
  }

  static fromRaw(data) {
    return new this().fromRaw(data);
  }
}

/**
 * RecordData
 */

class RecordData {
  inject(rd) {
    assert(rd instanceof this.constructor);

    for (const key of Object.keys(rd))
      this[key] = rd[key];

    return this;
  }

  clone() {
    const rr = new this.constructor();
    return rr.inject(this);
  }

  getSize(c) {
    return 0;
  }

  toWriter(bw, c) {
    return bw;
  }

  fromReader(br, c) {
    return this;
  }

  toRaw(c) {
    const size = this.getSize(c);
    const bw = bio.write(size);
    this.toWriter(bw, c);
    return bw.render();
  }

  fromRaw(data, c) {
    const br = bio.read(data);
    return this.fromReader(br, c);
  }

  static fromReader(br, c) {
    return new this().fromReader(br, c);
  }

  static fromRaw(data, c) {
    return new this().fromRaw(data, c);
  }
}

/**
 * UNKNOWN Record
 */

class UNKNOWNRecord extends RecordData {
  constructor() {
    super();
    this.data = DUMMY; // rdata
  }

  getSize() {
    return this.data.length;
  }

  toWriter(bw) {
    bw.writeBytes(this.data);
    return bw;
  }

  fromReader(br) {
    this.data = br.readBytes(br.left());
    return this;
  }
}

/**
 * A Record
 * Address Record
 * @see https://tools.ietf.org/html/rfc1035
 */

class ARecord extends RecordData {
  constructor() {
    super();
    this.address = '0.0.0.0';
  }

  getSize() {
    return 4;
  }

  toWriter(bw) {
    const ip = IP.decode(this.address);
    assert(ip.length === 4);
    bw.writeBytes(ip);
    return bw;
  }

  fromReader(br) {
    this.address = IP.encode(br.readBytes(4));
    return this;
  }
}

/**
 * NS Record
 * Name Server Record
 * @see https://tools.ietf.org/html/rfc1035#page-12
 */

class NSRecord extends RecordData {
  constructor() {
    super();
    this.ns = '.';
  }

  getSize() {
    return sizeName(this.ns);
  }

  toWriter(bw) {
    writeNameBW(bw, this.ns);
    return bw;
  }

  fromReader(br) {
    this.ns = readNameBR(br);
    return this;
  }
}

/**
 * MD Record
 * Mail Destination Record (obsolete)
 * @see https://tools.ietf.org/html/rfc883
 * @see https://tools.ietf.org/html/rfc973
 */

class MDRecord extends RecordData {
  constructor() {
    super();
    this.md = '.';
  }

  getSize() {
    return sizeName(this.md);
  }

  toWriter(bw) {
    writeNameBW(bw, this.md);
    return bw;
  }

  fromReader(br) {
    this.md = readNameBR(br);
    return this;
  }
}

/**
 * MF Record
 * Mail Forwarder Record (obsolete)
 * @see https://tools.ietf.org/html/rfc883
 * @see https://tools.ietf.org/html/rfc973
 */

class MFRecord extends RecordData {
  constructor() {
    super();
    this.mf = '.';
  }

  getSize() {
    return sizeName(this.mf);
  }

  toWriter(bw) {
    writeNameBW(bw, this.mf);
    return bw;
  }

  fromReader(br) {
    this.mf = readNameBR(br);
    return this;
  }
}

/**
 * CNAME Record
 * Canonical Name Record
 * @see https://tools.ietf.org/html/rfc1035#page-12
 */

class CNAMERecord extends RecordData {
  constructor() {
    super();
    this.target = '.';
  }

  getSize() {
    return sizeName(this.target);
  }

  toWriter(bw) {
    writeNameBW(bw, this.target);
    return bw;
  }

  fromReader(br) {
    this.target = readNameBR(br);
    return this;
  }
}

/**
 * SOA Record
 * Start of Authority Record
 * @see https://tools.ietf.org/html/rfc1035#page-12
 * @see https://tools.ietf.org/html/rfc2308
 */

class SOARecord extends RecordData {
  constructor() {
    super();
    this.ns = '.';
    this.mbox = '.';
    this.serial = 0;
    this.refresh = 0;
    this.retry = 0;
    this.expire = 0;
    this.minttl = 0;
  }

  getSize() {
    return sizeName(this.ns) + sizeName(this.mbox) + 20;
  }

  toWriter(bw) {
    writeNameBW(bw, this.ns);
    writeNameBW(bw, this.mbox);
    bw.writeU32BE(this.serial);
    bw.writeU32BE(this.refresh);
    bw.writeU32BE(this.retry);
    bw.writeU32BE(this.expire);
    bw.writeU32BE(this.minttl);
    return bw;
  }

  fromReader(br) {
    this.ns = readNameBR(br);
    this.mbox = readNameBR(br);
    this.serial = br.readU32BE();
    this.refresh = br.readU32BE();
    this.retry = br.readU32BE();
    this.expire = br.readU32BE();
    this.minttl = br.readU32BE();
    return this;
  }
}

/**
 * MB Record
 * Mailbox Record (expiremental)
 * @see https://tools.ietf.org/html/rfc883
 * @see https://tools.ietf.org/html/rfc1035
 * @see https://tools.ietf.org/html/rfc2505
 */

class MBRecord extends RecordData {
  constructor() {
    super();
    this.mb = '.';
  }

  getSize() {
    return sizeName(this.mb);
  }

  toWriter(bw) {
    writeNameBW(bw, this.mb);
    return bw;
  }

  fromReader(br) {
    this.mb = readNameBR(br);
    return this;
  }
}

/**
 * MG Record
 * Mail Group Record (experimental)
 * @see https://tools.ietf.org/html/rfc883
 * @see https://tools.ietf.org/html/rfc1035
 * @see https://tools.ietf.org/html/rfc2505
 */

class MGRecord extends RecordData {
  constructor() {
    super();
    this.mg = '.';
  }

  getSize() {
    return sizeName(this.mg);
  }

  toWriter(bw) {
    writeNameBW(bw, this.mg);
    return bw;
  }

  fromReader(br) {
    this.mg = readNameBR(br);
    return this;
  }
}

/**
 * MR Record
 * Mail Rename Record (experimental)
 * @see https://tools.ietf.org/html/rfc883
 * @see https://tools.ietf.org/html/rfc1035
 * @see https://tools.ietf.org/html/rfc2505
 */

class MRRecord extends RecordData {
  constructor() {
    super();
    this.mr = '.';
  }

  getSize() {
    return sizeName(this.mr);
  }

  toWriter(bw) {
    writeNameBW(bw, this.mr);
    return bw;
  }

  fromReader(br) {
    this.mr = readNameBR(br);
    return this;
  }
}

/**
 * NULL Record
 * Null Record (obsolete)
 * @see https://tools.ietf.org/html/rfc883
 * @see https://tools.ietf.org/html/rfc1035
 */

class NULLRecord extends UNKNOWNRecord {
  constructor() {
    super();
  }
}

/**
 * WKS Record
 * Well-known Services Record (deprecated)
 * @see https://tools.ietf.org/html/rfc883
 * @see https://tools.ietf.org/html/rfc1035
 * @see https://tools.ietf.org/html/rfc1123
 * @see https://tools.ietf.org/html/rfc1127
 */

class WKSRecord extends RecordData {
  constructor() {
    super();
    this.address = '0.0.0.0';
    this.protocol = 0;
    this.bitmap = DUMMY;
  }

  getSize() {
    return 5 + this.bitmap.length;
  }

  toWriter(bw) {
    const ip = IP.decode(this.address);
    assert(ip.length === 4);
    bw.writeBytes(ip);
    bw.writeU8(this.protocol);
    bw.writeBytes(this.bitmap);
    return bw;
  }

  fromReader(br) {
    this.address = IP.encode(br.readBytes(4));
    this.protocol = br.readU8();
    this.bitmap = br.readBytes(br.left());
    return this;
  }
}

/**
 * PTR Record
 * Pointer Record
 * @see https://tools.ietf.org/html/rfc1035
 */

class PTRRecord extends RecordData {
  constructor() {
    super();
    this.ptr = '.';
  }

  getSize() {
    return sizeName(this.ptr);
  }

  toWriter(bw) {
    writeNameBW(bw, this.ptr);
    return bw;
  }

  fromReader(br) {
    this.ptr = readNameBR(br);
    return this;
  }
}

/**
 * HINFO Record
 * Host Information Record (not-in-use)
 * @see https://tools.ietf.org/html/rfc883
 */

class HINFORecord extends RecordData {
  constructor() {
    super();
    this.cpu = '';
    this.os = '';
  }

  getSize() {
    return 1 + this.cpu.length + 1 + this.os.length;
  }

  toWriter(bw) {
    bw.writeU8(this.cpu.length);
    bw.writeString(this.cpu, 'ascii');
    bw.writeU8(this.os.length);
    bw.writeString(this.os, 'ascii');
    return bw;
  }

  fromReader(br) {
    this.cpu = br.readString('ascii', br.readU8());
    this.os = br.readString('ascii', br.readU8());
    return this;
  }
}

/**
 * MINFO Record
 * Mail Info Record (experimental)
 * @see https://tools.ietf.org/html/rfc883
 * @see https://tools.ietf.org/html/rfc1035
 * @see https://tools.ietf.org/html/rfc2505
 */

class MINFORecord extends RecordData {
  constructor() {
    super();
    this.rmail = '.';
    this.email = '.';
  }

  getSize() {
    return sizeName(this.rmail) + sizeName(this.email);
  }

  toWriter(bw) {
    writeNameBW(bw, this.rmail);
    writeNameBW(bw, this.email);
    return bw;
  }

  fromReader(br) {
    this.rmail = readNameBR(br);
    this.email = readNameBR(br);
    return this;
  }
}

/**
 * MX Record
 * Mail Exchange Record
 * @see https://tools.ietf.org/html/rfc1035#page-12
 * @see https://tools.ietf.org/html/rfc7505
 */

class MXRecord extends RecordData {
  constructor() {
    super();
    this.preference = 0;
    this.mx = '.';
  }

  getSize() {
    return 2 + sizeName(this.mx);
  }

  toWriter(bw) {
    bw.writeU16BE(this.preference);
    writeNameBW(bw, this.mx);
    return bw;
  }

  fromReader(br) {
    this.preference = br.readU16BE();
    this.mx = readNameBR(br);
    return this;
  }
}

/**
 * TXT Record
 * Text Record
 * @see https://tools.ietf.org/html/rfc1035#page-12
 */

class TXTRecord extends RecordData {
  constructor() {
    super();
    this.txt = [];
  }

  getSize() {
    let size = 0;
    for (const txt of this.txt)
      size += 1 + txt.length;
    return size;
  }

  toWriter(bw) {
    for (const txt of this.txt) {
      bw.writeU8(txt.length);
      bw.writeString(txt, 'ascii');
    }
    return bw;
  }

  fromReader(br) {
    while (br.left())
      this.txt.push(br.readString('ascii', br.readU8()));
    return this;
  }
}

/**
 * RP Record
 * Responsible Person Record
 * @see https://tools.ietf.org/html/rfc1183
 */

class RPRecord extends RecordData {
  constructor() {
    super();
    this.mbox = '';
    this.txt = '';
  }

  getSize() {
    return sizeName(this.mbox) + sizeName(this.txt);
  }

  toWriter(bw) {
    writeNameBW(bw, this.mbox);
    writeNameBW(bw, this.txt);
    return bw;
  }

  fromReader(br) {
    this.mbox = readNameBR(br);
    this.txt = readNameBR(br);
    return this;
  }
}

/**
 * AFSDB Record
 * AFS Database Record
 * @see https://tools.ietf.org/html/rfc1183
 */

class AFSDBRecord extends RecordData {
  constructor() {
    super();
    this.subtype = 0;
    this.hostname = '.';
  }

  getSize() {
    return 2 + sizeName(this.hostname);
  }

  toWriter(bw) {
    bw.writeU16BE(this.subtype);
    writeNameBW(bw, this.hostname);
    return bw;
  }

  fromReader(br) {
    this.subtype = br.readU16BE();
    this.hostname = readNameBR(br);
    return this;
  }
}

/**
 * X25Record
 * X25 Record (not-in-use)
 * @see https://tools.ietf.org/html/rfc1183
 */

class X25Record extends RecordData {
  constructor() {
    super();
    this.psdnAddress = '';
  }

  getSize() {
    return 1 + this.psdnAddress.length;
  }

  toWriter(bw) {
    bw.writeU8(this.psdnAddress.length);
    bw.writeString(this.psdnAddress, 'ascii');
    return bw;
  }

  fromReader(br) {
    this.psdnAddress = br.readString('ascii', br.readU8());
    return this;
  }
}

/**
 * ISDN Record
 * ISDN Record (not-in-use)
 * @see https://tools.ietf.org/html/rfc1183
 */

class ISDNRecord extends RecordData {
  constructor() {
    super();
    this.address = '';
    this.sa = '';
  }

  getSize() {
    return 1 + this.address.length + 1 + this.sa.length;
  }

  toWriter(bw) {
    bw.writeU8(this.address.length);
    bw.writeString(this.address, 'ascii');
    bw.writeU8(this.sa.length);
    bw.writeString(this.sa, 'ascii');
    return bw;
  }

  fromReader(br) {
    this.address = br.readString('ascii', br.readU8());
    this.sa = br.readString('ascii', br.readU8());
    return this;
  }
}

/**
 * RT Record
 * RT Record (not-in-use)
 * @see https://tools.ietf.org/html/rfc1183
 */

class RTRecord extends RecordData {
  constructor() {
    super();
    this.preference = 0;
    this.host = '.';
  }

  getSize() {
    return 2 + sizeName(this.host);
  }

  toWriter(bw) {
    bw.writeU16BE(this.preference);
    writeNameBW(bw, this.host);
    return bw;
  }

  fromReader(br) {
    this.preference = br.readU16BE();
    this.host = readNameBR(br);
    return this;
  }
}

/**
 * NSAP Record
 * Network Service Access Point Record (not-in-use)
 * @see https://tools.ietf.org/html/rfc1706
 */

class NSAPRecord extends RecordData {
  constructor() {
    super();
    this.nsap = DUMMY;
  }

  getSize() {
    return this.nsap.length;
  }

  toWriter(bw) {
    bw.writeBytes(this.nsap);
    return bw;
  }

  fromReader(br) {
    this.nsap = br.readBytes(br.left());
    return this;
  }
}

/**
 * NSAPPTR Record
 * Network Service Access Point PTR Record (not-in-use)
 * @see https://tools.ietf.org/html/rfc1348
 */

class NSAPPTRRecord extends PTRRecord {
  constructor() {
    super();
  }
}

/**
 * SIG Record
 * Signature Record (obsolete)
 * @see https://tools.ietf.org/html/rfc2065
 * @see https://tools.ietf.org/html/rfc3755
 */

class SIGRecord extends RecordData {
  constructor() {
    super();
    this.typeCovered = 0;
    this.algorithm = 0;
    this.labels = 0;
    this.origTTL = 0;
    this.expiration = 0;
    this.inception = 0;
    this.keyTag = 0;
    this.signerName = '.';
    this.signature = DUMMY;
  }

  getSize() {
    return 18 + sizeName(this.signerName) + this.signature.length;
  }

  toWriter(bw) {
    bw.writeU16BE(this.typeCovered);
    bw.writeU8(this.algorithm);
    bw.writeU8(this.labels);
    bw.writeU32BE(this.origTTL);
    bw.writeU32BE(this.expiration);
    bw.writeU32BE(this.inception);
    bw.writeU16BE(this.keyTag);
    writeNameBW(bw, this.signerName);
    bw.writeBytes(this.signature);
    return bw;
  }

  fromReader(br) {
    this.typeCovered = br.readU16BE();
    this.algorithm = br.readU8();
    this.labels = br.readU8();
    this.origTTL = br.readU32BE();
    this.expiration = br.readU32BE();
    this.inception = br.readU32BE();
    this.keyTag = br.readU16BE();
    this.signerName = readNameBR(br);
    this.signature = br.readBytes(br.left());
    return this;
  }

  toTBS() {
    const signerName = this.signerName;
    const signature = this.signature;

    this.signerName = signerName.toLowerCase();
    this.signature = DUMMY;

    let raw = null;

    try {
      raw = this.toRaw();
    } finally {
      this.signerName = signerName;
      this.signature = signature;
    }

    return raw;
  }

  validityPeriod(t) {
    if (t == null)
      t = util.now();

    return t >= this.inception && t <= this.expiration;
  }

  toJSON() {
    return {
      type: this.constructor.name,
      typeCovered: this.typeCovered,
      algorithm: this.algorithm,
      labels: this.labels,
      origTTL: this.origTTL,
      expiration: this.expiration,
      inception: this.inception,
      keyTag: this.keyTag,
      signerName: this.signerName,
      signature: this.signature.toString('base64')
    };
  }

  inspect() {
    return this.toJSON();
  }
}

/**
 * KEY Record
 * Key Record (obsolete)
 * @see https://tools.ietf.org/html/rfc2065
 * @see https://tools.ietf.org/html/rfc3755
 */

class KEYRecord extends RecordData {
  constructor() {
    super();
    this.flags = 0;
    this.protocol = 0;
    this.algorithm = 0;
    this.publicKey = DUMMY;
  }

  getSize() {
    return 4 + this.publicKey.length;
  }

  toWriter(bw) {
    bw.writeU16BE(this.flags);
    bw.writeU8(this.protocol);
    bw.writeU8(this.algorithm);
    bw.writeBytes(this.publicKey);
    return bw;
  }

  fromReader(br) {
    this.flags = br.readU16BE();
    this.protocol = br.readU8();
    this.algorithm = br.readU8();
    this.publicKey = br.readBytes(br.left());
    return this;
  }

  keyTag(raw) {
    if (this.algorithm === 0 /* RSAMD5 */) {
      const key = this.publicKey;

      if (key.length < 2)
        return 0;

      return key.readUInt16BE(key.length - 2, true);
    }

    if (!raw)
      raw = this.toRaw();

    let tag = 0;

    for (let i = 0; i < raw.length; i++) {
      const ch = raw[i];

      if (i & 1)
        tag += ch;
      else
        tag += ch << 8;

      tag |= 0;
    }

    tag += (tag >>> 16) & 0xffff;
    tag &= 0xffff;

    return tag;
  }

  toJSON() {
    return {
      type: this.constructor.name,
      flags: this.flags,
      protocol: this.protocol,
      algorithm: this.algorithm,
      publicKey: this.publicKey.toString('base64'),
      keyTag: this.keyTag()
    };
  }

  inspect() {
    return this.toJSON();
  }
}

/**
 * PX Record
 * Pointer to X400 Mapping Information Record (not-in-use)
 * @see https://tools.ietf.org/html/rfc2163
 */

class PXRecord extends RecordData {
  constructor() {
    super();
    this.preference = 0;
    this.map822 = '';
    this.mapx400 = '';
  }

  getSize() {
    return 2 + sizeName(this.map822) + sizeName(this.mapx400);
  }

  toWriter(bw) {
    bw.writeU16BE(this.preference);
    writeNameBW(bw, this.map822);
    writeNameBW(bw, this.mapx400);
    return bw;
  }

  fromReader(br) {
    this.preference = br.readU16BE();
    this.map822 = readNameBR(br);
    this.mapx400 = readNameBR(br);
    return this;
  }
}

/**
 * GPOS Record
 * Geographical Position Record (deprecated)
 * @see https://tools.ietf.org/html/rfc1712
 */

class GPOSRecord extends RecordData {
  constructor() {
    super();
    this.longitude = '';
    this.latitude = '';
    this.altitude = '';
  }

  getSize() {
    return 3
      + this.longitude.length
      + this.latitude.length
      + this.altitude.length;
  }

  toWriter(bw) {
    bw.writeU8(this.longitude.length);
    bw.writeString(this.longitude, 'ascii');
    bw.writeU8(this.latitude.length);
    bw.writeString(this.latitude, 'ascii');
    bw.writeU8(this.altitude.length);
    bw.writeString(this.altitude, 'ascii');
    return bw;
  }

  fromReader(br) {
    this.longitude = br.readString('ascii', br.readU8());
    this.latitude = br.readString('ascii', br.readU8());
    this.altitude = br.readString('ascii', br.readU8());
    return this;
  }
}

/**
 * AAAA Record
 * IPv6 Address Record
 * @see https://tools.ietf.org/html/rfc3596
 */

class AAAARecord extends RecordData {
  constructor() {
    super();
    this.address = '::';
  }

  getSize() {
    return 16;
  }

  toWriter(bw) {
    const ip = IP.decode(this.address);
    assert(ip.length === 16);
    bw.writeBytes(ip);
    return bw;
  }

  fromReader(br) {
    this.address = IP.encode(br.readBytes(16));
    return this;
  }
}

/**
 * LOC Record
 * Location Record
 * @see https://tools.ietf.org/html/rfc1876
 */

class LOCRecord extends RecordData {
  constructor() {
    super();
    this.version = 0;
    this.size = 0;
    this.horizPre = 0;
    this.vertPre = 0;
    this.latitude = 0;
    this.longitude = 0;
    this.altitude = 0;
  }

  getSize() {
    return 16;
  }

  toWriter(bw) {
    bw.writeU8(this.version);
    bw.writeU8(this.size);
    bw.writeU8(this.horizPre);
    bw.writeU8(this.vertPre);
    bw.writeU32BE(this.latitude);
    bw.writeU32BE(this.longitude);
    bw.writeU32BE(this.altitude);
    return bw;
  }

  fromReader(br) {
    this.version = br.readU8();
    this.size = br.readU8();
    this.horizPre = br.readU8();
    this.vertPre = br.readU8();
    this.latitude = br.readU32BE();
    this.longitude = br.readU32BE();
    this.altitude = br.readU32BE();
    return this;
  }
}

/**
 * NXT Record
 * Next Domain Record (obsolete)
 * @see https://tools.ietf.org/html/rfc2065#section-5.2
 * @see https://tools.ietf.org/html/rfc3755
 */

class NXTRecord extends RecordData {
  constructor() {
    super();
    this.nextDomain = '.';
    this.typeBitmap = DUMMY;
  }

  setTypes(types) {
    this.typeBitmap = toBitmap(types);
    return this;
  }

  getTypes() {
    return fromBitmap(this.typeBitmap);
  }

  hasType(type) {
    return hasType(this.typeBitmap, type);
  }

  getSize() {
    return sizeName(this.nextDomain) + this.typeBitmap.length;
  }

  toWriter(bw) {
    writeNameBW(bw, this.nextDomain);
    bw.writeBytes(this.typeBitmap);
    return bw;
  }

  fromReader(br) {
    this.nextDomain = readNameBR(br);
    this.typeBitmap = br.readBytes(br.left());
    return this;
  }
}

/**
 * EID Record
 * Endpoint Identifier Record (not-in-use)
 * @see http://ana-3.lcs.mit.edu/~jnc/nimrod/dns.txt
 */

class EIDRecord extends RecordData {
  constructor() {
    super();
    this.endpoint = DUMMY;
  }

  getSize() {
    return this.endpoint.length;
  }

  toWriter(bw) {
    bw.writeBytes(this.endpoint);
    return bw;
  }

  fromReader(br) {
    this.endpoint = br.readBytes(br.left());
    return this;
  }
}

/**
 * NIMLOC Record
 * Nimrod Locator Record (not-in-use)
 * @see http://ana-3.lcs.mit.edu/~jnc/nimrod/dns.txt
 */

class NIMLOCRecord extends RecordData {
  constructor() {
    super();
    this.locator = DUMMY;
  }

  getSize() {
    return this.locator.length;
  }

  toWriter(bw) {
    bw.writeBytes(this.locator);
    return bw;
  }

  fromReader(br) {
    this.locator = br.readBytes(br.left());
    return this;
  }
}

/**
 * SRV Record
 * Service Locator Record
 * @see https://tools.ietf.org/html/rfc2782
 */

class SRVRecord extends RecordData {
  constructor() {
    super();
    this.priority = 0;
    this.weight = 0;
    this.port = 0;
    this.target = '.';
  }

  getSize() {
    return 6 + sizeName(this.target);
  }

  toWriter(bw) {
    bw.writeU16BE(this.priority);
    bw.writeU16BE(this.weight);
    bw.writeU16BE(this.port);
    writeNameBW(bw, this.target);
    return bw;
  }

  fromReader(br) {
    this.priority = br.readU16BE();
    this.weight = br.readU16BE();
    this.port = br.readU16BE();
    this.target = readNameBR(br);
    return this;
  }
}

/**
 * ATMA Record
 * Asynchronous Transfer Mode Record (not-in-use)
 * @see http://www.broadband-forum.org/ftp/pub/approved-specs/af-dans-0152.000.pdf
 */

class ATMARecord extends RecordData {
  constructor() {
    super();
    this.format = 0;
    this.address = DUMMY;
  }

  getSize() {
    return 1 + this.address.length;
  }

  toWriter(bw) {
    bw.writeU8(this.format);
    bw.writeBytes(this.address);
    return bw;
  }

  fromReader(br) {
    this.format = br.readU8();
    this.address = br.readBytes(br.left());
    return this;
  }
}

/**
 * NAPTR Record
 * Naming Authority Pointer Record
 * @see https://tools.ietf.org/html/rfc3403
 */

class NAPTRRecord extends RecordData {
  constructor() {
    super();
    this.order = 0;
    this.preference = 0;
    this.flags = '';
    this.service = '';
    this.regexp = '';
    this.replacement = '';
  }

  getSize() {
    return 4
      + 1 + this.flags.length
      + 1 + this.service.length
      + 1 + this.regexp.length
      + sizeName(this.replacement);
  }

  toWriter(bw) {
    bw.writeU16BE(this.order);
    bw.writeU16BE(this.preference);
    bw.writeU8(this.flags.length);
    bw.writeString(this.flags, 'ascii');
    bw.writeU8(this.service.length);
    bw.writeString(this.service, 'ascii');
    bw.writeU8(this.regexp.length);
    bw.writeString(this.regexp, 'ascii');
    writeNameBW(bw, this.replacement);
    return bw;
  }

  fromReader(br) {
    this.order = br.readU16BE();
    this.preference = br.readU16BE();
    this.flags = br.readString('ascii', br.readU8());
    this.service = br.readString('ascii', br.readU8());
    this.regexp = br.readString('ascii', br.readU8());
    this.replacement = readNameBR(br);
    return this;
  }
}

/**
 * KX Record
 * Key Exchanger Record
 * @see https://tools.ietf.org/html/rfc2230
 */

class KXRecord extends RecordData {
  constructor() {
    super();
    this.preference = 0;
    this.exchanger = '';
  }

  getSize() {
    return 2 + sizeName(this.exchanger);
  }

  toWriter(bw) {
    bw.writeU16BE(this.preference);
    writeNameBW(bw, this.exchanger);
    return bw;
  }

  fromReader(br) {
    this.preference = br.readU16BE();
    this.exchanger = readNameBR(br);
    return this;
  }
}

/**
 * CERT Record
 * Certificate Record
 * @see https://tools.ietf.org/html/rfc4398
 */

class CERTRecord extends RecordData {
  constructor() {
    super();
    this.type = 0;
    this.keyTag = 0;
    this.algorithm = 0;
    this.certificate = DUMMY;
  }

  getSize() {
    return 5 + this.certificate.length;
  }

  toWriter(bw) {
    bw.writeU16BE(this.type);
    bw.writeU16BE(this.keyTag);
    bw.writeU8(this.algorithm);
    bw.writeBytes(this.certificate);
    return bw;
  }

  fromReader(br) {
    this.type = br.readU16BE();
    this.keyTag = br.readU16BE();
    this.algorithm = br.readU8();
    this.certificate = br.readBytes(br.left());
    return this;
  }
}

/**
 * A6Record
 * A IPv6 Record (historic)
 * @see https://tools.ietf.org/html/rfc2874#section-3.1.1
 * @see https://tools.ietf.org/html/rfc6563
 */

class A6Record extends RecordData {
  constructor() {
    super();
    this.address = '::';
    this.prefix = '';
  }

  getSize() {
    return 17 + this.prefix.length;
  }

  toWriter(bw) {
    bw.writeU8(this.prefix.length);
    const ip = IP.decode(this.address);
    assert(ip.length === 16);
    bw.writeBytes(ip);
    bw.writeString(this.prefix, 'ascii');
    return bw;
  }

  fromReader(br) {
    const prefixLen = br.readU8();
    this.address = IP.encode(br.readBytes(16));
    this.prefix = br.readString('ascii', prefixLen);
    return this;
  }
}

/**
 * DNAME Record
 * Delegation Name Record
 * @see https://tools.ietf.org/html/rfc6672
 */

class DNAMERecord extends CNAMERecord {
  constructor() {
    super();
  }
}

/**
 * OPT Record
 * Option Record (EDNS) (pseudo-record)
 * @see https://tools.ietf.org/html/rfc6891#section-6.1
 */

class OPTRecord extends RecordData {
  constructor() {
    super();
    this.options = [];
  }

  getSize() {
    let size = 0;
    for (const opt of this.options)
      size += opt.getSize();
    return size;
  }

  toWriter(bw) {
    for (const opt of this.options)
      opt.toWriter(bw);
    return bw;
  }

  fromReader(br) {
    while (br.left())
      this.options.push(Option.fromReader(br));
    return this;
  }
}

/**
 * APL Record
 * Address Prefix List Record (not-in-use)
 * @see https://tools.ietf.org/html/rfc3123
 */

class APLRecord extends RecordData {
  constructor() {
    super();
    this.family = 0;
    this.prefix = 0;
    this.n = 0;
    this.afd = DUMMY;
  }

  getSize() {
    return 4 + this.afd.length;
  }

  toWriter(bw) {
    bw.writeU16BE(this.family);
    bw.writeU8(this.prefix);
    bw.writeU8((this.n << 7) | this.afd.length);
    bw.writeBytes(this.afd);
    return bw;
  }

  fromReader(br) {
    this.family = br.readU16BE();
    this.prefix = br.readU8();

    const field = br.readU8();
    const n = field >>> 7;
    const len = field & 0x7f;

    this.n = n;
    this.data = br.readBytes(len);

    return this;
  }
}

/**
 * DS Record
 * Delegation Signer
 * @see https://tools.ietf.org/html/rfc4034
 */

class DSRecord extends RecordData {
  constructor() {
    super();
    this.keyTag = 0;
    this.algorithm = 0;
    this.digestType = 0;
    this.digest = DUMMY;
  }

  getSize() {
    return 4 + this.digest.length;
  }

  toWriter(bw) {
    bw.writeU16BE(this.keyTag);
    bw.writeU8(this.algorithm);
    bw.writeU8(this.digestType);
    bw.writeBytes(this.digest);
    return bw;
  }

  fromReader(br) {
    this.keyTag = br.readU16BE();
    this.algorithm = br.readU8();
    this.digestType = br.readU8();
    this.digest = br.readBytes(br.left());
    return this;
  }

  toJSON() {
    return {
      type: this.constructor.name,
      keyTag: this.keyTag,
      algorithm: this.algorithm,
      digestType: this.digestType,
      digest: this.digest.toString('hex')
    };
  }

  inspect() {
    return this.toJSON();
  }
}

/**
 * SSHFP Record
 * SSH Finger Print Record
 * @see https://tools.ietf.org/html/rfc4255
 */

class SSHFPRecord extends RecordData {
  constructor() {
    super();
    this.algorithm = 0;
    this.type = 0;
    this.fingerprint = DUMMY;
  }

  getSize() {
    return 2 + this.fingerprint.length;
  }

  toWriter(bw) {
    bw.writeU8(this.algorithm);
    bw.writeU8(this.type);
    bw.writeBytes(this.fingerprint);
    return bw;
  }

  fromReader(br) {
    this.algorithm = br.readU8();
    this.type = br.readU8();
    this.fingerprint = br.readBytes(br.left());
    return this;
  }
}

/**
 * IPSECKEY Record
 * IPsec Key Record
 * @see https://tools.ietf.org/html/rfc4025
 */

class IPSECKEYRecord extends RecordData {
  constructor() {
    super();
    this.precedence = 0;
    this.gatewayType = 0;
    this.algorithm = 0;
    this.target = '';
    this.publicKey = DUMMY;
  }

  getSize() {
    let size = 3;

    switch (this.gatewayType) {
      case 0:
        size += 0;
        break;
      case 1:
        size += 4;
        break;
      case 2:
        size += 16;
        break;
      case 3:
        size += sizeName(this.target);
        break;
    }

    size += this.publicKey.length;

    return size;
  }

  toWriter(bw) {
    bw.writeU8(this.precedence);
    bw.writeU8(this.gatewayType);
    bw.writeU8(this.algorithm);

    switch (this.gatewayType) {
      case 0:
        break;
      case 1: {
        const ip = IP.decode(this.target);
        assert(ip.length === 4);
        bw.writeBytes(ip);
        break;
      }
      case 2: {
        const ip = IP.decode(this.target);
        assert(ip.length === 16);
        bw.writeBytes(ip);
        break;
      }
      case 3:
        writeNameBW(bw, this.target);
        break;
      default:
        throw new Error('Unknown gateway type.');
    }

    bw.writeBytes(this.publicKey);

    return bw;
  }

  fromReader(br) {
    this.precedence = br.readU8();
    this.gatewayType = br.readU8();
    this.algorithm = br.readU8();

    switch (this.gatewayType) {
      case 0:
        break;
      case 1:
        this.target = IP.encode(br.readBytes(4));
        break;
      case 2:
        this.target = IP.encode(br.readBytes(16));
        break;
      case 3:
        this.target = readNameBR(br);
        break;
      default:
        throw new Error('Unknown gateway type.');
    }

    this.publicKey = br.readBytes(br.left());

    return this;
  }
}

/**
 * RRSIG Record
 * DNSSEC Signature Record
 * @see https://tools.ietf.org/html/rfc4034
 */

class RRSIGRecord extends SIGRecord {
  constructor() {
    super();
  }
}

/**
 * NSEC Record
 * Next Secure Record
 * @see https://tools.ietf.org/html/rfc4034
 */

class NSECRecord extends RecordData {
  constructor() {
    super();
    this.nextDomain = '.';
    this.typeBitmap = DUMMY;
  }

  setTypes(types) {
    this.typeBitmap = toBitmap(types);
    return this;
  }

  getTypes() {
    return fromBitmap(this.typeBitmap);
  }

  hasType(type) {
    return hasType(this.typeBitmap, type);
  }

  getSize() {
    return sizeName(this.nextDomain) + this.typeBitmap.length;
  }

  toWriter(bw) {
    writeNameBW(bw, this.nextDomain);
    bw.writeBytes(this.typeBitmap);
    return bw;
  }

  fromReader(br) {
    this.nextDomain = readNameBR(br);
    this.typeBitmap = br.readBytes(br.left());
    return this;
  }
}

/**
 * DNSKEY Record
 * DNS Key Record
 * @see https://tools.ietf.org/html/rfc4034
 */

class DNSKEYRecord extends KEYRecord {
  constructor() {
    super();
  }
}

/**
 * DHCID Record
 * DHCP Identifier Record
 * @see https://tools.ietf.org/html/rfc4701
 */

class DHCIDRecord extends RecordData {
  constructor() {
    super();
    this.digest = DUMMY;
  }

  getSize() {
    return this.digest.length;
  }

  toWriter(bw) {
    bw.writeBytes(this.digest);
    return bw;
  }

  fromReader(br) {
    this.digest = br.readBytes(br.left());
    return this;
  }
}

/**
 * NSEC3Record
 * Next Secure Record (v3)
 * @see https://tools.ietf.org/html/rfc5155
 */

class NSEC3Record extends RecordData {
  constructor() {
    super();
    this.hash = 0;
    this.flags = 0;
    this.iterations = 0;
    this.salt = DUMMY;
    this.nextDomain = DUMMY;
    this.typeBitmap = DUMMY;
  }

  setTypes(types) {
    this.typeBitmap = toBitmap(types);
    return this;
  }

  getTypes() {
    return fromBitmap(this.typeBitmap);
  }

  hasType(type) {
    return hasType(this.typeBitmap, type);
  }

  getSize() {
    return 6
      + this.salt.length
      + this.nextDomain.length
      + this.typeBitmap.length;
  }

  toWriter(bw) {
    bw.writeU8(this.hash);
    bw.writeU8(this.flags);
    bw.writeU16BE(this.iterations);
    bw.writeU8(this.salt.length);
    bw.writeBytes(this.salt);
    bw.writeU8(this.nextDomain.length);
    bw.writeBytes(this.nextDomain);
    bw.writeBytes(this.typeBitmap);
    return bw;
  }

  fromReader(br) {
    this.hash = br.readU8();
    this.flags = br.readU8();
    this.iterations = br.readU16BE();
    this.salt = br.readBytes(br.readU8());
    this.nextDomain = br.readBytes(br.readU8());
    this.typeBitmap = br.readBytes(br.left());
    return this;
  }

  toJSON() {
    return {
      type: this.constructor.name,
      hash: this.hash,
      flags: this.flags,
      iterations: this.iterations,
      salt: this.salt.toString('hex'),
      nextDomain: this.nextDomain.toString('hex'),
      typeBitmap: this.getTypes()
    };
  }

  inspect() {
    return this.toJSON();
  }
}

/**
 * NSEC3PARAM Record
 * NSEC3 Params Record
 * @see https://tools.ietf.org/html/rfc5155
 */

class NSEC3PARAMRecord extends RecordData {
  constructor() {
    super();
    this.hash = 0;
    this.flags = 0;
    this.iterations = 0;
    this.salt = DUMMY;
  }

  getSize() {
    return 5 + this.salt.length;
  }

  toWriter(bw) {
    bw.writeU8(this.hash);
    bw.writeU8(this.flags);
    bw.writeU16BE(this.iterations);
    bw.writeU8(this.salt.length);
    bw.writeBytes(this.salt);
    return bw;
  }

  fromReader(br) {
    this.hash = br.readU8();
    this.flags = br.readU8();
    this.iterations = br.readU16BE();
    this.salt = br.readBytes(br.readU8());
    return this;
  }
}

/**
 * TLSA Record
 * TLSA Certificate Association Record
 * @see https://tools.ietf.org/html/rfc6698
 */

class TLSARecord extends RecordData {
  constructor() {
    super();
    this.usage = 0;
    this.selector = 0;
    this.matchingType = 0;
    this.certificate = DUMMY;
  }

  getSize() {
    return 3 + this.certificate.length;
  }

  toWriter(bw) {
    bw.writeU8(this.usage);
    bw.writeU8(this.selector);
    bw.writeU8(this.matchingType);
    bw.writeBytes(this.certificate);
    return bw;
  }

  fromReader(br) {
    this.usage = br.readU8();
    this.selector = br.readU8();
    this.matchingType = br.readU8();
    this.certificate = br.readBytes(br.left());
    return this;
  }
}

/**
 * SMIMEA Record
 * S/MIME Certificate Association Record
 * @see https://tools.ietf.org/html/rfc8162
 */

class SMIMEARecord extends TLSARecord {
  constructor() {
    super();
  }
}

/**
 * HIP Record
 * Host Identity Protocol Record
 * @see https://tools.ietf.org/html/rfc8005
 */

class HIPRecord extends RecordData {
  constructor() {
    super();
    this.algorithm = 0;
    this.hit = DUMMY;
    this.publicKey = DUMMY;
    this.rendezvousServers = [];
  }

  getSize() {
    let size = 4;
    size += this.hit.length;
    size += this.publicKey.length;
    for (const name of this.rendezvousServers)
      size += sizeName(name);
    return size;
  }

  toWriter(bw) {
    bw.writeU8(this.hit.length);
    bw.writeU8(this.algorithm);
    bw.writeU16BE(this.publicKey.length);
    bw.writeBytes(this.hit);
    bw.writeBytes(this.publicKey);
    for (const name of this.rendezvousServers)
      writeNameBW(bw, name);
    return bw;
  }

  fromReader(br) {
    const hitLen = br.readU8();

    this.algorithm = br.readU8();

    const keyLen = br.readU16BE();

    this.hit = br.readBytes(hitLen);
    this.publicKey = br.readBytes(keyLen);

    while (br.left())
      this.rendezvousServers.push(readNameBR(br));

    return this;
  }
}

/**
 * NINFO Record
 * Zone Status Information (proposed)
 * @see https://www.iana.org/assignments/dns-parameters/NINFO/ninfo-completed-template
 */

class NINFORecord extends RecordData {
  constructor() {
    super();
    this.zsData = [];
  }

  getSize() {
    let size = 0;
    for (const zs of this.zsData)
      size += 1 + zs.length;
    return size;
  }

  toWriter(bw) {
    for (const zs of this.zsData) {
      bw.writeU8(zs.length);
      bw.writeString(zs, 'ascii');
    }
    return bw;
  }

  fromReader(br) {
    while (br.left())
      this.zsData.push(br.readString('ascii', br.readU8()));
    return this;
  }
}

/**
 * RKEY Record
 * R Key Record (proposed)
 * @see https://www.iana.org/assignments/dns-parameters/RKEY/rkey-completed-template
 */

class RKEYRecord extends KEYRecord {
  constructor() {
    super();
  }
}

/**
 * TALINK Record
 * Trust Authorities Link Record (proposed)
 * @see https://www.iana.org/assignments/dns-parameters/TALINK/talink-completed-template
 */

class TALINKRecord extends RecordData {
  constructor() {
    super();
    this.prevName = '.';
    this.nextName = '.';
  }

  getSize() {
    return sizeName(this.prevName) + sizeName(this.nextName);
  }

  toWriter(bw) {
    writeNameBW(bw, this.prevName);
    writeNameBW(bw, this.nextName);
    return bw;
  }

  fromReader(br) {
    this.prevName = readNameBR(br);
    this.nextName = readNameBR(br);
    return this;
  }
}

/**
 * CDS Record
 * Child DS Record
 * @see https://tools.ietf.org/html/rfc7344
 */

class CDSRecord extends DSRecord {
  constructor() {
    super();
  }
}

/**
 * CDNSKEY Record
 * Child DNSKEY Record
 * @see https://tools.ietf.org/html/rfc7344
 */

class CDNSKEYRecord extends KEYRecord {
  constructor() {
    super();
  }
}

/**
 * OPENPGPKEY Record
 * OpenPGP Public Key Record
 * @see https://tools.ietf.org/html/rfc7929
 */

class OPENPGPKEYRecord extends RecordData {
  constructor() {
    super();
    this.publicKey = DUMMY;
  }

  getSize() {
    return this.publicKey.length;
  }

  toWriter(bw) {
    bw.writeBytes(this.publicKey);
    return bw;
  }

  fromReader(br) {
    this.publicKey = br.readBytes(br.left());
    return this;
  }
}

/**
 * CSYNC Record
 * Child Synchronization Record
 * @see https://tools.ietf.org/html/rfc7477
 */

class CSYNCRecord extends RecordData {
  constructor() {
    super();
    this.serial = 0;
    this.flags = 0;
    this.typeBitmap = DUMMY;
  }

  setTypes(types) {
    this.typeBitmap = toBitmap(types);
    return this;
  }

  getTypes() {
    return fromBitmap(this.typeBitmap);
  }

  hasType(type) {
    return hasType(this.typeBitmap, type);
  }

  getSize() {
    return 6 + this.typeBitmap.length;
  }

  toWriter(bw) {
    bw.writeU32BE(this.serial);
    bw.writeU16BE(this.flags);
    bw.writeBytes(this.typeBitmap);
    return bw;
  }

  fromReader(br) {
    this.serial = br.readU32BE();
    this.flags = br.readU16BE();
    this.typeBitmap = br.readBytes(br.left());
    return this;
  }
}

/**
 * SPF Record
 * Sender Policy Framework Record (obsolete)
 * @see https://tools.ietf.org/html/rfc4408
 * @see https://tools.ietf.org/html/rfc7208
 */

class SPFRecord extends TXTRecord {
  constructor() {
    super();
  }
}

/**
 * UINFO Record
 * UINFO Record (obsolete)
 * (No Documentation)
 */

class UINFORecord extends RecordData {
  constructor() {
    super();
    this.uinfo = '';
  }

  getSize() {
    return 1 + this.uinfo.length;
  }

  toWriter(bw) {
    bw.writeU8(this.uinfo.length);
    bw.writeString(this.uinfo, 'ascii');
    return bw;
  }

  fromReader(br) {
    this.uinfo = br.readString('ascii', br.readU8());
    return this;
  }
}

/**
 * UID Record
 * UID Record (obsolete)
 * (No Documentation)
 */

class UIDRecord extends RecordData {
  constructor() {
    super();
    this.uid = 0;
  }

  getSize() {
    return 4;
  }

  toWriter(bw) {
    bw.writeU32BE(this.uid);
    return bw;
  }

  fromReader(br) {
    this.uid = br.readU32BE();
    return this;
  }
}

/**
 * GID Record
 * GID Record (obsolete)
 * (No Documentation)
 */

class GIDRecord extends RecordData {
  constructor() {
    super();
    this.gid = 0;
  }

  getSize() {
    return 4;
  }

  toWriter(bw) {
    bw.writeU32BE(this.gid);
    return bw;
  }

  fromReader(br) {
    this.gid = br.readU32BE();
    return this;
  }
}

/**
 * UNSPEC Record
 * UNSPEC Record (obsolete)
 * (No Documentation)
 */

class UNSPECRecord extends UNKNOWNRecord {
  constructor() {
    super();
  }
}

/**
 * NID Record
 * Node Identifier Record
 * @see https://tools.ietf.org/html/rfc6742
 */

class NIDRecord extends RecordData {
  constructor() {
    super();
    this.preference = 0;
    this.nodeID = DUMMY8;
  }

  getSize() {
    return 10;
  }

  toWriter(bw) {
    bw.writeU16BE(this.preference);
    bw.writeBytes(this.nodeID);
    return bw;
  }

  fromReader(br) {
    this.preference = br.readU16BE();
    this.nodeID = br.readBytes(8);
    return this;
  }
}

/**
 * L32Record
 * Locator 32 Record
 * @see https://tools.ietf.org/html/rfc6742
 */

class L32Record extends RecordData {
  constructor() {
    super();
    this.preference = 0;
    this.locator32 = '0.0.0.0';
  }

  getSize() {
    return 6;
  }

  toWriter(bw) {
    bw.writeU16BE(this.preference);
    const ip = IP.decode(this.locator32);
    assert(ip.length === 4);
    bw.writeBytes(ip);
    return bw;
  }

  fromReader(br) {
    this.preference = br.readU16BE();
    this.locator32 = IP.encode(br.readBytes(4));
    return this;
  }
}

/**
 * L64Record
 * Locator 64 Record
 * @see https://tools.ietf.org/html/rfc6742
 */

class L64Record extends RecordData {
  constructor() {
    super();
    this.preference = 0;
    this.locator64 = DUMMY8;
  }

  getSize() {
    return 10;
  }

  toWriter(bw) {
    bw.writeU16BE(this.preference);
    bw.writeBytes(this.locator64);
    return bw;
  }

  fromReader(br) {
    this.preference = br.readU16BE();
    this.locator64 = br.readBytes(8);
    return this;
  }
}

/**
 * LP Record
 * Locator Pointer Record
 * @see https://tools.ietf.org/html/rfc6742
 */

class LPRecord extends RecordData {
  constructor() {
    super();
    this.preference = 0;
    this.fqdn = '';
  }

  getSize() {
    return 2 + sizeName(this.fqdn);
  }

  toWriter(bw) {
    bw.writeU16BE(this.preference);
    writeNameBW(bw, this.fqdn);
    return bw;
  }

  fromReader(br) {
    this.preference = br.readU16BE();
    this.fqdn = readNameBR(br);
    return this;
  }
}

/**
 * EUI48Record
 * Extended Unique Identifier Record (48 bit)
 * @see https://tools.ietf.org/html/rfc7043
 */

class EUI48Record extends RecordData {
  constructor() {
    super();
    this.address = DUMMY6;
  }

  getSize() {
    return 6;
  }

  toWriter(bw) {
    bw.writeBytes(this.address);
    return bw;
  }

  fromReader(br) {
    this.address = br.readBytes(6);
    return this;
  }
}

/**
 * EUI64Record
 * Extended Unique Identifier Record (64 bit)
 * @see https://tools.ietf.org/html/rfc7043
 */

class EUI64Record extends RecordData {
  constructor() {
    super();
    this.address = DUMMY8;
  }

  getSize() {
    return 8;
  }

  toWriter(bw) {
    bw.writeBytes(this.address);
    return bw;
  }

  fromReader(br) {
    this.address = br.readBytes(8);
    return this;
  }
}

/**
 * URI Record
 * Uniform Resource Identifier Record
 * @see https://tools.ietf.org/html/rfc7553
 */

class URIRecord extends RecordData {
  constructor() {
    super();
    this.priority = 0;
    this.weight = 0;
    this.target = '';
  }

  getSize() {
    return 4 + this.target.length;
  }

  toWriter(bw) {
    bw.writeU16BE(this.priority);
    bw.writeU16BE(this.weight);
    bw.writeString(this.target, 'ascii');
    return bw;
  }

  fromReader(br) {
    this.priority = br.readU16BE();
    this.weight = br.readU16BE();
    this.target = br.readString('ascii', br.left());
    return this;
  }
}

/**
 * CAA Record
 * Certification Authority Authorization Record
 * @see https://tools.ietf.org/html/rfc6844
 */

class CAARecord extends RecordData {
  constructor() {
    super();
    this.flag = 0;
    this.tag = '';
    this.value = '';
  }

  getSize() {
    return 1 + 1 + this.tag.length + this.value.length;
  }

  toWriter(bw) {
    bw.writeU8(this.flag);
    bw.writeU8(this.tag.length);
    bw.writeString(this.tag, 'ascii');
    bw.writeString(this.value, 'ascii');
    return bw;
  }

  fromReader(br) {
    this.flag = br.readU8();
    this.tag = br.readString('ascii', br.readU8());
    this.value = br.readString('ascii', br.left());
    return this;
  }
}

/**
 * AVC Record
 * Application Visibility and Control (proposed)
 * @see https://www.iana.org/assignments/dns-parameters/AVC/avc-completed-template
 */

class AVCRecord extends TXTRecord {
  constructor() {
    super();
  }
}

/**
 * TKEY Record
 * Transaction Key Record
 * @see https://tools.ietf.org/html/rfc2930
 */

class TKEYRecord extends RecordData {
  constructor() {
    super();
    this.algorithm = '';
    this.inception = 0;
    this.expiration = 0;
    this.mode = 0;
    this.error = 0;
    this.key = DUMMY;
    this.other = DUMMY;
  }

  getSize() {
    let size = 0;
    size += sizeName(this.algorithm);
    size += 16;
    size += this.key.length;
    size += this.other.length;
    return size;
  }

  toWriter(bw) {
    writeNameBW(bw, this.algorithm);
    bw.writeU32BE(this.inception);
    bw.writeU32BE(this.expiration);
    bw.writeU16BE(this.mode);
    bw.writeU16BE(this.error);
    bw.writeU16BE(this.key.length);
    bw.writeBytes(this.key);
    bw.writeU16BE(this.other.length);
    bw.writeBytes(this.other);
    return bw;
  }

  fromReader(br) {
    this.algorithm = readNameBR(br);
    this.inception = br.readU32BE();
    this.expiration = br.readU32BE();
    this.mode = br.readU16BE();
    this.error = br.readU16BE();
    this.key = br.readBytes(br.readU16BE());
    this.other = br.readBytes(br.readU16BE());
    return this;
  }
}

/**
 * TSIG Record
 * Transaction Signature Record
 * @see https://tools.ietf.org/html/rfc2845
 */

class TSIGRecord extends RecordData {
  constructor() {
    super();
    this.algorithm = '';
    this.timeSigned = 0;
    this.fudge = 0;
    this.mac = DUMMY;
    this.origID = 0;
    this.error = 0;
    this.other = DUMMY;
  }

  getSize() {
    let size = 16;
    size += sizeName(this.algorithm);
    size += this.mac.length;
    size += this.other.length;
    return size;
  }

  toWriter(bw) {
    writeNameBW(bw, this.algorithm);
    bw.writeU16BE((this.timeSigned / 0x100000000) >>> 0);
    bw.writeU32BE(this.timeSigned >>> 0);
    bw.writeU16BE(this.fudge);
    bw.writeU16BE(this.mac.length);
    bw.writeBytes(this.mac);
    bw.writeU16BE(this.origID);
    bw.writeU16BE(this.error);
    bw.writeU16BE(this.other.length);
    bw.writeBytes(this.other);
    return bw;
  }

  fromReader(br) {
    this.algorithm = readNameBR(br);
    this.timeSigned = br.readU16BE() * 0x100000000 + br.readU32BE();
    this.fudge = br.readU16BE();
    this.mac = br.readBytes(br.readU16BE());
    this.origID = br.readU16BE();
    this.error = br.readU16BE();
    this.other = br.readBytes(br.readU16BE());
    return this;
  }
}

/**
 * ANY Record
 * All Cached Records (pseudo-resource)
 * @see https://tools.ietf.org/html/rfc1035#page-12
 */

class ANYRecord extends RecordData {
  constructor() {
    super();
  }
}

/**
 * TA Record
 * Trust Authorities Record
 * @see http://www.watson.org/~weiler/INI1999-19.pdf
 */

class TARecord extends RecordData {
  constructor() {
    super();
    this.keyTag = 0;
    this.algorithm = 0;
    this.digestType = 0;
    this.digest = DUMMY;
  }

  getSize() {
    return 4 + this.digest.length;
  }

  toWriter(bw) {
    bw.writeU16BE(this.keyTag);
    bw.writeU8(this.algorithm);
    bw.writeU8(this.digestType);
    bw.writeBytes(this.digest);
    return bw;
  }

  fromReader(br) {
    this.keyTag = br.readU16BE();
    this.algorithm = br.readU8();
    this.digestType = br.readU8();
    this.digest = br.readBytes(br.left());
    return this;
  }
}

/**
 * DLV Record
 * DNSSEC Lookaside Validation Record
 * @see https://tools.ietf.org/html/rfc4431
 */

class DLVRecord extends DSRecord {
  constructor() {
    super();
  }
}

/**
 * Option Field
 * @see https://tools.ietf.org/html/rfc6891#section-6.1
 */

class Option extends RecordData {
  constructor() {
    super();
    this.code = 0;
    this.option = new UNKNOWNOption();
  }

  getSize() {
    return 4 + this.option.getSize();
  }

  toWriter(bw) {
    bw.writeU16BE(this.code);
    bw.writeU16BE(this.option.getSize());
    this.option.toWriter(bw);
    return bw;
  }

  fromReader(br) {
    this.code = br.readU16BE();
    this.option = readOption(this.code, br);
    return this;
  }
}

/**
 * UNKNOWN Option
 * EDNS Unknown Option
 */

class UNKNOWNOption extends RecordData {
  constructor() {
    super();
    this.data = DUMMY;
  }

  getSize() {
    return this.data.length;
  }

  toWriter(bw) {
    bw.writeBytes(this.data);
    return bw;
  }

  fromReader(br) {
    this.data = br.readBytes(br.left());
    return this;
  }
}

/**
 * LLQ Option
 * EDNS Long Lived Queries Option
 * @see http://tools.ietf.org/html/draft-sekar-dns-llq-01
 */

class LLQOption extends RecordData {
  constructor() {
    super();
    this.version = 0;
    this.opcode = 0;
    this.error = 0;
    this.id = DUMMY8;
    this.leaseLife = 0;
  }

  getSize() {
    return 18;
  }

  toWriter(bw) {
    bw.writeU16BE(this.version);
    bw.writeU16BE(this.opcode);
    bw.writeU16BE(this.error);
    bw.writeBytes(this.id);
    bw.writeU32BE(this.leaseLife);
    return bw;
  }

  fromReader(br) {
    this.version = br.readU16BE();
    this.opcode = br.readU16BE();
    this.error = br.readU16BE();
    this.id = br.readBytes(8);
    this.leaseLife = br.readU32BE();
    return this;
  }
}

/**
 * UL Option
 * EDNS Update Lease Option
 * @see http://files.dns-sd.org/draft-sekar-dns-ul.txt
 */

class ULOption extends RecordData {
  constructor() {
    super();
    this.lease = 0;
  }

  getSize() {
    return 4;
  }

  toWriter(bw) {
    bw.writeU32BE(this.lease);
    return bw;
  }

  fromReader(br) {
    this.lease = br.readU32BE();
    return this;
  }
}

/**
 * NSID Option
 * Nameserver Identifier Option
 * @see https://tools.ietf.org/html/rfc5001
 */

class NSIDOption extends RecordData {
  constructor() {
    super();
    this.nsid = DUMMY;
  }

  getSize() {
    return this.nsid.length;
  }

  toWriter(bw) {
    bw.writeBytes(this.nsid);
    return bw;
  }

  fromReader(br) {
    this.nsid = br.readBytes(br.left());
    return this;
  }
}

/**
 * DAU Option
 * EDNS DNSSEC Algorithm Understood Option
 * @see https://tools.ietf.org/html/rfc6975
 */

class DAUOption extends RecordData {
  constructor() {
    super();
    this.algCode = DUMMY;
  }

  getSize() {
    return this.algCode.length;
  }

  toWriter(bw) {
    bw.writeBytes(this.algCode);
    return bw;
  }

  fromReader(br) {
    this.algCode = br.readBytes(br.left());
    return this;
  }
}

/**
 * DHU Option
 * EDNS DS Hash Understood Option
 * @see https://tools.ietf.org/html/rfc6975
 */

class DHUOption extends DAUOption {
  constructor() {
    super();
  }
}

/**
 * N3U Option
 * EDNS NSEC3 Hash Understood Option
 * @see https://tools.ietf.org/html/rfc6975
 */

class N3UOption extends DAUOption {
  constructor() {
    super();
  }
}

/**
 * SUBNET Option
 * EDNS Subnet Option
 * @see https://tools.ietf.org/html/rfc7871
 */

class SUBNETOption extends RecordData {
  constructor() {
    super();
    this.family = 1;
    this.sourceNetmask = 0;
    this.sourceScope = 0;
    this.address = '0.0.0.0';
  }

  getSize() {
    switch (this.family) {
      case 0:
        return 4;
      case 1:
        return 8;
      case 2:
        return 16;
    }
    return 4;
  }

  toWriter(bw) {
    bw.writeU16BE(this.family);
    bw.writeU8(this.sourceNetmask);
    bw.writeU8(this.sourceScope);

    switch (this.family) {
      case 1: {
        const ip = IP.decode(this.address);
        assert(ip.length === 4);
        bw.writeByest(ip);
        break;
      }
      case 2: {
        const ip = IP.decode(this.address);
        assert(ip.length === 16);
        bw.writeBytes(ip);
        break;
      }
    }

    return bw;
  }

  fromReader(br) {
    this.family = br.readU16BE();
    this.sourceNetmask = br.readU8();
    this.sourceScope = br.readU8();

    switch (this.family) {
      case 1:
        this.address = IP.encode(br.readBytes(4));
        break;
      case 2:
        this.address = IP.encode(br.readBytes(16));
        break;
    }

    return this;
  }
}

/**
 * EXPIRE Option
 * EDNS Expire Option
 * @see https://tools.ietf.org/html/rfc7314
 */

class EXPIREOption extends RecordData {
  constructor() {
    super();
    this.expire = 0;
  }

  getSize() {
    return 4;
  }

  toWriter(bw) {
    bw.writeU32BE(this.expire);
    return bw;
  }

  fromReader(br) {
    this.expire = br.readU32BE();
    return this;
  }
}

/**
 * COOKIE Option
 * EDNS Cookie Option
 * @see https://tools.ietf.org/html/rfc7873
 */

class COOKIEOption extends RecordData {
  constructor() {
    super();
    this.cookie = DUMMY;
  }

  getSize() {
    return this.cookie.length;
  }

  toWriter(bw) {
    bw.writeBytes(this.cookie);
    return bw;
  }

  fromReader(br) {
    this.cookie = br.readBytes(br.left());
    return this;
  }
}

/**
 * TCPKEEPALIVE Option
 * EDNS TCP Keep-Alive Option
 * @see https://tools.ietf.org/html/rfc7828
 */

class TCPKEEPALIVEOption extends RecordData {
  constructor() {
    super();
    this.length = 0;
    this.timeout = 0;
  }

  getSize() {
    return 4;
  }

  toWriter(bw) {
    bw.writeU16BE(this.length);
    bw.writeU16BE(this.timeout);
    return bw;
  }

  fromReader(br) {
    this.length = br.readU16BE();
    this.timeout = br.readU16BE();
    return this;
  }
}

/**
 * PADDING Option
 * EDNS Padding Option
 * @see https://tools.ietf.org/html/rfc7830
 */

class PADDINGOption extends RecordData {
  constructor() {
    super();
    this.padding = DUMMY;
  }

  getSize() {
    return this.padding.length;
  }

  toWriter(bw) {
    bw.writeBytes(this.padding);
    return bw;
  }

  fromReader(br) {
    this.padding = br.readBytes(br.left());
    return this;
  }
}

/**
 * LOCAL Option
 * EDNS Local Option
 * @see https://tools.ietf.org/html/rfc6891
 */

class LOCALOption extends RecordData {
  constructor() {
    super();
    this.data = DUMMY;
  }

  getSize() {
    return this.data.length;
  }

  toWriter(bw) {
    bw.writeBytes(this.data);
    return bw;
  }

  fromReader(br) {
    this.data = br.readBytes(br.left());
    return this;
  }
}

/*
 * Decode
 */

function decode(type, data) {
  switch (type) {
    case types.NONE:
      return UNKNOWNRecord.fromRaw(data);
    case types.A:
      return ARecord.fromRaw(data);
    case types.NS:
      return NSRecord.fromRaw(data);
    case types.MD:
      return MDRecord.fromRaw(data);
    case types.MF:
      return MFRecord.fromRaw(data);
    case types.CNAME:
      return CNAMERecord.fromRaw(data);
    case types.SOA:
      return SOARecord.fromRaw(data);
    case types.MB:
      return MBRecord.fromRaw(data);
    case types.MG:
      return MGRecord.fromRaw(data);
    case types.MR:
      return MRRecord.fromRaw(data);
    case types.NULL:
      return NULLRecord.fromRaw(data);
    case types.WKS:
      return WKSRecord.fromRaw(data);
    case types.PTR:
      return PTRRecord.fromRaw(data);
    case types.HINFO:
      return HINFORecord.fromRaw(data);
    case types.MINFO:
      return MINFORecord.fromRaw(data);
    case types.MX:
      return MXRecord.fromRaw(data);
    case types.TXT:
      return TXTRecord.fromRaw(data);
    case types.RP:
      return RPRecord.fromRaw(data);
    case types.AFSDB:
      return AFSDBRecord.fromRaw(data);
    case types.X25:
      return X25Record.fromRaw(data);
    case types.ISDN:
      return ISDNRecord.fromRaw(data);
    case types.RT:
      return RTRecord.fromRaw(data);
    case types.NSAP:
      return NSAPRecord.fromRaw(data);
    case types.NSAPPTR:
      return NSAPPTRRecord.fromRaw(data);
    case types.SIG:
      return SIGRecord.fromRaw(data);
    case types.KEY:
      return KEYRecord.fromRaw(data);
    case types.PX:
      return PXRecord.fromRaw(data);
    case types.GPOS:
      return GPOSRecord.fromRaw(data);
    case types.AAAA:
      return AAAARecord.fromRaw(data);
    case types.LOC:
      return LOCRecord.fromRaw(data);
    case types.NXT:
      return NXTRecord.fromRaw(data);
    case types.EID:
      return EIDRecord.fromRaw(data);
    case types.NIMLOC:
      return NIMLOCRecord.fromRaw(data);
    case types.SRV:
      return SRVRecord.fromRaw(data);
    case types.ATMA:
      return ATMARecord.fromRaw(data);
    case types.NAPTR:
      return NAPTRRecord.fromRaw(data);
    case types.KX:
      return KXRecord.fromRaw(data);
    case types.CERT:
      return CERTRecord.fromRaw(data);
    case types.A6:
      return A6Record.fromRaw(data);
    case types.DNAME:
      return DNAMERecord.fromRaw(data);
    case types.SINK:
      return UNKNOWNRecord.fromRaw(data);
    case types.OPT:
      return OPTRecord.fromRaw(data);
    case types.APL:
      return APLRecord.fromRaw(data);
    case types.DS:
      return DSRecord.fromRaw(data);
    case types.SSHFP:
      return SSHFPRecord.fromRaw(data);
    case types.IPSECKEY:
      return IPSECKEYRecord.fromRaw(data);
    case types.RRSIG:
      return RRSIGRecord.fromRaw(data);
    case types.NSEC:
      return NSECRecord.fromRaw(data);
    case types.DNSKEY:
      return DNSKEYRecord.fromRaw(data);
    case types.DHCID:
      return DHCIDRecord.fromRaw(data);
    case types.NSEC3:
      return NSEC3Record.fromRaw(data);
    case types.NSEC3PARAM:
      return NSEC3PARAMRecord.fromRaw(data);
    case types.TLSA:
      return TLSARecord.fromRaw(data);
    case types.SMIMEA:
      return SMIMEARecord.fromRaw(data);
    case types.HIP:
      return HIPRecord.fromRaw(data);
    case types.NINFO:
      return NINFORecord.fromRaw(data);
    case types.RKEY:
      return RKEYRecord.fromRaw(data);
    case types.TALINK:
      return TALINKRecord.fromRaw(data);
    case types.CDS:
      return CDSRecord.fromRaw(data);
    case types.CDNSKEY:
      return CDNSKEYRecord.fromRaw(data);
    case types.OPENPGPKEY:
      return OPENPGPKEYRecord.fromRaw(data);
    case types.CSYNC:
      return CSYNCRecord.fromRaw(data);
    case types.SPF:
      return SPFRecord.fromRaw(data);
    case types.UINFO:
      return UINFORecord.fromRaw(data);
    case types.UID:
      return UIDRecord.fromRaw(data);
    case types.GID:
      return GIDRecord.fromRaw(data);
    case types.UNSPEC:
      return UNSPECRecord.fromRaw(data);
    case types.NID:
      return NIDRecord.fromRaw(data);
    case types.L32:
      return L32Record.fromRaw(data);
    case types.L64:
      return L64Record.fromRaw(data);
    case types.LP:
      return LPRecord.fromRaw(data);
    case types.EUI48:
      return EUI48Record.fromRaw(data);
    case types.EUI64:
      return EUI64Record.fromRaw(data);
    case types.URI:
      return URIRecord.fromRaw(data);
    case types.CAA:
      return CAARecord.fromRaw(data);
    case types.AVC:
      return AVCRecord.fromRaw(data);
    case types.TSIG:
      return TSIGRecord.fromRaw(data);
    case types.TKEY:
      return TKEYRecord.fromRaw(data);
    case types.ANY:
      return ANYRecord.fromRaw(data);
    case types.TA:
      return TARecord.fromRaw(data);
    case types.DLV:
      return DLVRecord.fromRaw(data);
    default:
      return UNKNOWNRecord.fromRaw(data);
  }
}

function read(type, br) {
  const size = br.readU16BE();
  const {data, offset} = br;
  const len = offset + size;

  assert(len <= data.length);

  const cdata = data.slice(0, len);
  const cbr = bio.read(cdata);
  cbr.offset = offset;

  let rd = null;

  switch (type) {
    case types.NONE:
      rd = UNKNOWNRecord.fromReader(cbr);
      break;
    case types.A:
      rd = ARecord.fromReader(cbr);
      break;
    case types.NS:
      rd = NSRecord.fromReader(cbr);
      break;
    case types.MD:
      rd = MDRecord.fromReader(cbr);
      break;
    case types.MF:
      rd = MFRecord.fromReader(cbr);
      break;
    case types.CNAME:
      rd = CNAMERecord.fromReader(cbr);
      break;
    case types.SOA:
      rd = SOARecord.fromReader(cbr);
      break;
    case types.MB:
      rd = MBRecord.fromReader(cbr);
      break;
    case types.MG:
      rd = MGRecord.fromReader(cbr);
      break;
    case types.MR:
      rd = MRRecord.fromReader(cbr);
      break;
    case types.NULL:
      rd = NULLRecord.fromReader(cbr);
      break;
    case types.WKS:
      rd = WKSRecord.fromReader(cbr);
      break;
    case types.PTR:
      rd = PTRRecord.fromReader(cbr);
      break;
    case types.HINFO:
      rd = HINFORecord.fromReader(cbr);
      break;
    case types.MINFO:
      rd = MINFORecord.fromReader(cbr);
      break;
    case types.MX:
      rd = MXRecord.fromReader(cbr);
      break;
    case types.TXT:
      rd = TXTRecord.fromReader(cbr);
      break;
    case types.RP:
      rd = RPRecord.fromReader(cbr);
      break;
    case types.AFSDB:
      rd = AFSDBRecord.fromReader(cbr);
      break;
    case types.X25:
      rd = X25Record.fromReader(cbr);
      break;
    case types.ISDN:
      rd = ISDNRecord.fromReader(cbr);
      break;
    case types.RT:
      rd = RTRecord.fromReader(cbr);
      break;
    case types.NSAP:
      rd = NSAPRecord.fromReader(cbr);
      break;
    case types.NSAPPTR:
      rd = NSAPPTRRecord.fromReader(cbr);
      break;
    case types.SIG:
      rd = SIGRecord.fromReader(cbr);
      break;
    case types.KEY:
      rd = KEYRecord.fromReader(cbr);
      break;
    case types.PX:
      rd = PXRecord.fromReader(cbr);
      break;
    case types.GPOS:
      rd = GPOSRecord.fromReader(cbr);
      break;
    case types.AAAA:
      rd = AAAARecord.fromReader(cbr);
      break;
    case types.LOC:
      rd = LOCRecord.fromReader(cbr);
      break;
    case types.NXT:
      rd = NXTRecord.fromReader(cbr);
      break;
    case types.EID:
      rd = EIDRecord.fromReader(cbr);
      break;
    case types.NIMLOC:
      rd = NIMLOCRecord.fromReader(cbr);
      break;
    case types.SRV:
      rd = SRVRecord.fromReader(cbr);
      break;
    case types.ATMA:
      rd = ATMARecord.fromReader(cbr);
      break;
    case types.NAPTR:
      rd = NAPTRRecord.fromReader(cbr);
      break;
    case types.KX:
      rd = KXRecord.fromReader(cbr);
      break;
    case types.CERT:
      rd = CERTRecord.fromReader(cbr);
      break;
    case types.A6:
      rd = A6Record.fromReader(cbr);
      break;
    case types.DNAME:
      rd = DNAMERecord.fromReader(cbr);
      break;
    case types.SINK:
      rd = UNKNOWNRecord.fromReader(cbr);
      break;
    case types.OPT:
      rd = OPTRecord.fromReader(cbr);
      break;
    case types.APL:
      rd = APLRecord.fromReader(cbr);
      break;
    case types.DS:
      rd = DSRecord.fromReader(cbr);
      break;
    case types.SSHFP:
      rd = SSHFPRecord.fromReader(cbr);
      break;
    case types.IPSECKEY:
      rd = IPSECKEYRecord.fromReader(cbr);
      break;
    case types.RRSIG:
      rd = RRSIGRecord.fromReader(cbr);
      break;
    case types.NSEC:
      rd = NSECRecord.fromReader(cbr);
      break;
    case types.DNSKEY:
      rd = DNSKEYRecord.fromReader(cbr);
      break;
    case types.DHCID:
      rd = DHCIDRecord.fromReader(cbr);
      break;
    case types.NSEC3:
      rd = NSEC3Record.fromReader(cbr);
      break;
    case types.NSEC3PARAM:
      rd = NSEC3PARAMRecord.fromReader(cbr);
      break;
    case types.TLSA:
      rd = TLSARecord.fromReader(cbr);
      break;
    case types.SMIMEA:
      rd = SMIMEARecord.fromReader(cbr);
      break;
    case types.HIP:
      rd = HIPRecord.fromReader(cbr);
      break;
    case types.NINFO:
      rd = NINFORecord.fromReader(cbr);
      break;
    case types.RKEY:
      rd = RKEYRecord.fromReader(cbr);
      break;
    case types.TALINK:
      rd = TALINKRecord.fromReader(cbr);
      break;
    case types.CDS:
      rd = CDSRecord.fromReader(cbr);
      break;
    case types.CDNSKEY:
      rd = CDNSKEYRecord.fromReader(cbr);
      break;
    case types.OPENPGPKEY:
      rd = OPENPGPKEYRecord.fromReader(cbr);
      break;
    case types.CSYNC:
      rd = CSYNCRecord.fromReader(cbr);
      break;
    case types.SPF:
      rd = SPFRecord.fromReader(cbr);
      break;
    case types.UINFO:
      rd = UINFORecord.fromReader(cbr);
      break;
    case types.UID:
      rd = UIDRecord.fromReader(cbr);
      break;
    case types.GID:
      rd = GIDRecord.fromReader(cbr);
      break;
    case types.UNSPEC:
      rd = UNSPECRecord.fromReader(cbr);
      break;
    case types.NID:
      rd = NIDRecord.fromReader(cbr);
      break;
    case types.L32:
      rd = L32Record.fromReader(cbr);
      break;
    case types.L64:
      rd = L64Record.fromReader(cbr);
      break;
    case types.LP:
      rd = LPRecord.fromReader(cbr);
      break;
    case types.EUI48:
      rd = EUI48Record.fromReader(cbr);
      break;
    case types.EUI64:
      rd = EUI64Record.fromReader(cbr);
      break;
    case types.URI:
      rd = URIRecord.fromReader(cbr);
      break;
    case types.CAA:
      rd = CAARecord.fromReader(cbr);
      break;
    case types.AVC:
      rd = AVCRecord.fromReader(cbr);
      break;
    case types.TSIG:
      rd = TSIGRecord.fromReader(cbr);
      break;
    case types.TKEY:
      rd = TKEYRecord.fromReader(cbr);
      break;
    case types.ANY:
      rd = ANYRecord.fromReader(cbr);
      break;
    case types.TA:
      rd = TARecord.fromReader(cbr);
      break;
    case types.DLV:
      rd = DLVRecord.fromReader(cbr);
      break;
    default:
      rd = UNKNOWNRecord.fromReader(cbr);
      break;
  }

  br.offset = cbr.offset;

  return rd;
}

function decodeOption(code, data) {
  switch (code) {
    case options.LLQ:
      return LLQOption.fromRaw(data);
    case options.UL:
      return ULOption.fromRaw(data);
    case options.NSID:
      return NSIDOption.fromRaw(data);
    case options.DAU:
      return DAUOption.fromRaw(data);
    case options.DHU:
      return DHUOption.fromRaw(data);
    case options.N3U:
      return N3UOption.fromRaw(data);
    case options.SUBNET:
      return SUBNETOption.fromRaw(data);
    case options.EXPIRE:
      return EXPIREOption.fromRaw(data);
    case options.COOKIE:
      return COOKIEOption.fromRaw(data);
    case options.TCPKEEPALIVE:
      return TCPKEEPALIVEOption.fromRaw(data);
    case options.PADDING:
      return PADDINGOption.fromRaw(data);
    default:
      if (code >= options.LOCALSTART && code <= options.LOCALEND)
        return LOCALOption.fromRaw(data);
      return UNKNOWNOption.fromRaw(data);
  }
}

function readOption(code, br) {
  const size = br.readU16BE();
  const {data, offset} = br;
  const len = offset + size;

  assert(len <= data.length);

  const cdata = data.slice(0, len);
  const cbr = bio.read(cdata);
  cbr.offset = offset;

  let opt = null;

  switch (code) {
    case options.LLQ:
      opt = LLQOption.fromReader(cbr);
      break;
    case options.UL:
      opt = ULOption.fromReader(cbr);
      break;
    case options.NSID:
      opt = NSIDOption.fromReader(cbr);
      break;
    case options.DAU:
      opt = DAUOption.fromReader(cbr);
      break;
    case options.DHU:
      opt = DHUOption.fromReader(cbr);
      break;
    case options.N3U:
      opt = N3UOption.fromReader(cbr);
      break;
    case options.SUBNET:
      opt = SUBNETOption.fromReader(cbr);
      break;
    case options.EXPIRE:
      opt = EXPIREOption.fromReader(cbr);
      break;
    case options.COOKIE:
      opt = COOKIEOption.fromReader(cbr);
      break;
    case options.TCPKEEPALIVE:
      opt = TCPKEEPALIVEOption.fromReader(cbr);
      break;
    case options.PADDING:
      opt = PADDINGOption.fromReader(cbr);
      break;
    default:
      if (code >= options.LOCALSTART && code <= options.LOCALEND)
        opt = LOCALOption.fromReader(cbr);
      else
        opt = UNKNOWNOption.fromReader(cbr);
      break;
  }

  br.offset = cbr.offset;

  return opt;
}

/*
 * Expose
 */

exports.opcodes = opcodes;
exports.flags = flags;
exports.codes = codes;
exports.types = types;
exports.classes = classes;
exports.eflags = eflags;
exports.options = options;

exports.Message = Message;
exports.Question = Question;
exports.Record = Record;
exports.RecordData = RecordData;

exports.UNKNOWNRecord = UNKNOWNRecord;
exports.ARecord = ARecord;
exports.NSRecord = NSRecord;
exports.MDRecord = MDRecord;
exports.MFRecord = MFRecord;
exports.CNAMERecord = CNAMERecord;
exports.SOARecord = SOARecord;
exports.MBRecord = MBRecord;
exports.MGRecord = MGRecord;
exports.MRRecord = MRRecord;
exports.NULLRecord = NULLRecord;
exports.WKSRecord = WKSRecord;
exports.PTRRecord = PTRRecord;
exports.HINFORecord = HINFORecord;
exports.MINFORecord = MINFORecord;
exports.MXRecord = MXRecord;
exports.TXTRecord = TXTRecord;
exports.RPRecord = RPRecord;
exports.AFSDBRecord = AFSDBRecord;
exports.X25Record = X25Record;
exports.ISDNRecord = ISDNRecord;
exports.RTRecord = RTRecord;
exports.NSAPRecord = NSAPRecord;
exports.NSAPPTRRecord = NSAPPTRRecord;
exports.SIGRecord = SIGRecord;
exports.KEYRecord = KEYRecord;
exports.PXRecord = PXRecord;
exports.GPOSRecord = GPOSRecord;
exports.AAAARecord = AAAARecord;
exports.LOCRecord = LOCRecord;
exports.NXTRecord = NXTRecord;
exports.EIDRecord = EIDRecord;
exports.NIMLOCRecord = NIMLOCRecord;
exports.SRVRecord = SRVRecord;
exports.ATMARecord = ATMARecord;
exports.NAPTRRecord = NAPTRRecord;
exports.KXRecord = KXRecord;
exports.CERTRecord = CERTRecord;
exports.A6Record = A6Record;
exports.DNAMERecord = DNAMERecord;
exports.OPTRecord = OPTRecord;
exports.APLRecord = APLRecord;
exports.DSRecord = DSRecord;
exports.SSHFPRecord = SSHFPRecord;
exports.IPSECKEYRecord = IPSECKEYRecord;
exports.RRSIGRecord = RRSIGRecord;
exports.NSECRecord = NSECRecord;
exports.DNSKEYRecord = DNSKEYRecord;
exports.DHCIDRecord = DHCIDRecord;
exports.NSEC3Record = NSEC3Record;
exports.NSEC3PARAMRecord = NSEC3PARAMRecord;
exports.TLSARecord = TLSARecord;
exports.SMIMEARecord = SMIMEARecord;
exports.HIPRecord = HIPRecord;
exports.NINFORecord = NINFORecord;
exports.RKEYRecord = RKEYRecord;
exports.TALINKRecord = TALINKRecord;
exports.CDSRecord = CDSRecord;
exports.CDNSKEYRecord = CDNSKEYRecord;
exports.OPENPGPKEYRecord = OPENPGPKEYRecord;
exports.CSYNCRecord = CSYNCRecord;
exports.SPFRecord = SPFRecord;
exports.UINFORecord = UINFORecord;
exports.UIDRecord = UIDRecord;
exports.GIDRecord = GIDRecord;
exports.UNSPECRecord = UNSPECRecord;
exports.NIDRecord = NIDRecord;
exports.L32Record = L32Record;
exports.L64Record = L64Record;
exports.LPRecord = LPRecord;
exports.EUI48Record = EUI48Record;
exports.EUI64Record = EUI64Record;
exports.URIRecord = URIRecord;
exports.CAARecord = CAARecord;
exports.AVCRecord = AVCRecord;
exports.TKEYRecord = TKEYRecord;
exports.TSIGRecord = TSIGRecord;
exports.ANYRecord = ANYRecord;
exports.TARecord = TARecord;
exports.DLVRecord = DLVRecord;

exports.Option = Option;
exports.UNKNOWNOption = UNKNOWNOption;
exports.LLQOption = LLQOption;
exports.ULOption = ULOption;
exports.NSIDOption = NSIDOption;
exports.DAUOption = DAUOption;
exports.DHUOption = DHUOption;
exports.N3UOption = N3UOption;
exports.SUBNETOption = SUBNETOption;
exports.EXPIREOption = EXPIREOption;
exports.COOKIEOption = COOKIEOption;
exports.TCPKEEPALIVEOption = TCPKEEPALIVEOption;
exports.PADDINGOption = PADDINGOption;
exports.LOCALOption = LOCALOption;

exports.decode = decode;
exports.read = read;

exports.decodeOption = decodeOption;
exports.readOption = readOption;
