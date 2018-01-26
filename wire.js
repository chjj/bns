'use strict';

// https://github.com/miekg/dns/blob/master/msg.go
// https://github.com/miekg/dns/blob/master/msg_helpers.go
// https://github.com/miekg/dns/blob/master/types.go
// https://github.com/tigeli/bind-utils/blob/1acae3ea5e3048ebd121d4837ef989b57a05e54c/lib/dns/name.c

const assert = require('assert');
const bio = require('bufio');
const encoding = require('./encoding');

const {
  sizeName,
  writeNameBW,
  readNameBR
} = encoding;

const types = {
  // valid rrtypes and qtypes
  NONE: 0,
  A: 1,
  NS: 2,
  MD: 3,
  MF: 4,
  CNAME: 5,
  SOA: 6,
  MB: 7,
  MG: 8,
  MR: 9,
  NULL: 10,
  PTR: 12,
  HINFO: 13,
  MINFO: 14,
  MX: 15,
  TXT: 16,
  RP: 17,
  AFSDB: 18,
  X25: 19,
  ISDN: 20,
  RT: 21,
  NSAPPTR: 23,
  SIG: 24,
  KEY: 25,
  PX: 26,
  GPOS: 27,
  AAAA: 28,
  LOC: 29,
  NXT: 30,
  EID: 31,
  NIMLOC: 32,
  SRV: 33,
  ATMA: 34,
  NAPTR: 35,
  KX: 36,
  CERT: 37,
  DNAME: 39,
  OPT: 41, // EDNS
  DS: 43,
  SSHFP: 44,
  RRSIG: 46,
  NSEC: 47,
  DNSKEY: 48,
  DHCID: 49,
  NSEC3: 50,
  NSEC3PARAM: 51,
  TLSA: 52,
  SMIMEA: 53,
  HIP: 55,
  NINFO: 56,
  RKEY: 57,
  TALINK: 58,
  CDS: 59,
  CDNSKEY: 60,
  OPENPGPKEY: 61,
  CSYNC: 62,
  SPF: 99,
  UINFO: 100,
  UID: 101,
  GID: 102,
  UNSPEC: 103,
  NID: 104,
  L32: 105,
  L64: 106,
  LP: 107,
  EUI48: 108,
  EUI64: 109,
  URI: 256,
  CAA: 257,
  AVC: 258,

  TKEY: 249,
  TSIG: 250,

  // qtypes only
  IXFR: 251,
  AXFR: 252,
  MAILB: 253,
  MAILA: 254,
  ANY: 255,
  TA: 32768,
  DLV: 32769,
  RESERVED: 65535
};

const classes = {
  // qclass
  INET: 1,
  CSNET: 2,
  CHAOS: 3,
  HESIOD: 4,
  NONE: 254,
  ANY: 255
};

const rcodes = {
  // Message Response Codes
  // https://www.iana.org/assignments/dns-parameters/dns-parameters.xhtml
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
  BADCOOKIE: 23, // Bad/missing Server Cookie
};

const opcodes = {
  QUERY: 0,
  IQUERY: 1,
  STATUS: 2,
  NOTIFY: 4,
  UPDATE: 5
};

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

class Message {
  constructor() {
    this.id = 0;
    this.response = false;
    this.opcode = 0;
    this.authoritative = false;
    this.truncated = false;
    this.recursionDesired = false;
    this.recursionAvailable = false;
    this.zero = false;
    this.authenticatedData = false;
    this.checkingDisabled = false;
    this.rcode = 0;
    this.question = [];
    this.answer = [];
    this.ns = [];
    this.extra = [];
  }

  getSize() {
    let size = 12;

    for (const q of this.question)
      size += q.getSize();

    for (const rr of this.answer)
      size += rr.getSize();

    for (const rr of this.ns)
      size += rr.getSize();

    for (const rr of this.extra)
      size += rr.getSize();

    return size;
  }

  toWriter(bw) {
    bw.writeU16BE(this.id);

    let bits = 0;

    if (this.response)
      bits |= flags.QR;

    if (this.opcode)
      bits |= (this.opcode & 0x0f) << 11;

    if (this.authoritative)
      bits |= flags.AA;

    if (this.truncated)
      bits |= flags.TC;

    if (this.recursionDesired)
      bits |= flags.RD;

    if (this.recursionAvailable)
      bits |= flags.RA;

    if (this.zero)
      bits |= flags.Z;

    if (this.authenticatedData)
      bits |= flags.AD;

    if (this.checkingDisabled)
      bits |= flags.CD;

    if (this.rcode)
      bits |= this.rcode & 0x0f;

    bw.writeU16BE(bits);
    bw.writeU16BE(this.question.length);
    bw.writeU16BE(this.answer.length);
    bw.writeU16BE(this.ns.length);
    bw.writeU16BE(this.extra.length);

    for (const q of this.question)
      q.toWriter(bw);

    for (const rr of this.answer)
      rr.toWriter(bw);

    for (const rr of this.ns)
      rr.toWriter(bw);

    for (const rr of this.extra)
      rr.toWriter(bw);

    return bw;
  }

  toRaw() {
    const size = this.getSize();
    return this.toWriter(bio.write(size)).render();
  }

  fromReader(br) {
    const id = br.readU16BE();
    const bits = br.readU16BE();
    const qdcount = br.readU16BE();
    const ancount = br.readU16BE();
    const nscount = br.readU16BE();
    const arcount = br.readU16BE();

    this.id = id;
    this.response = (bits & flags.QR) !== 0;
    this.opcode = (bits >>> 11) & 0x0f;
    this.authoritative = (bits & flags.AA) !== 0;
    this.truncated = (bits & flags.TC) !== 0;
    this.recursionDesired = (bits & flags.RD) !== 0;
    this.recursionAvailable = (bits & flags.RA) !== 0;
    this.zero = (bits & flags.Z) !== 0;
    this.authenticatedData = (bits & flags.AD) !== 0;
    this.checkingDisabled = (bits & flags.CD) !== 0;
    this.rcode = bits & 0x0f;

    for (let i = 0; i < qdcount; i++) {
      const q = Question.fromReader(br);
      this.question.push(q);
      if (br.left() === 0)
        return this;
    }

    for (let i = 0; i < ancount; i++) {
      const rr = Record.fromReader(br);
      this.answer.push(rr);
      if (br.left() === 0)
        return this;
    }

    for (let i = 0; i < nscount; i++) {
      const rr = Record.fromReader(br);
      this.ns.push(rr);
      if (br.left() === 0)
        return this;
    }

    for (let i = 0; i < arcount; i++) {
      const rr = Record.fromReader(br);
      this.extra.push(rr);
      if (br.left() === 0)
        return this;
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

class Question {
  constructor() {
    this.name = '';
    this.qtype = 0;
    this.qclass = 0;
  }

  getSize() {
    return sizeName(this.name) + 4;
  }

  toWriter(bw) {
    writeNameBW(bw, this.name);
    bw.writeU16BE(this.qtype);
    bw.writeU16BE(this.qclass);
    return bw;
  }

  toRaw() {
    const size = this.getSize();
    return this.toWriter(bio.write(size)).render();
  }

  fromReader(br) {
    this.name = readNameBR(br);

    if (br.left() === 0)
      return this;

    this.qtype = br.readU16BE();

    if (br.left() === 0)
      return this;

    this.qclass = br.readU16BE();

    if (br.left() === 0)
      return this;

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

class Record {
  constructor() {
    this.name = '';
    this.rrtype = 0;
    this.class = 0;
    this.ttl = 0;
    this.data = Buffer.alloc(0);
  }

  getSize() {
    return sizeName(this.name) + 10 + this.data.length;
  }

  toWriter(bw) {
    writeNameBW(bw, this.name);
    bw.writeU16BE(this.rrtype);
    bw.writeU16BE(this.class);
    bw.writeU32BE(this.ttl);
    bw.writeU16BE(this.data.length);
    bw.writeBytes(this.data);
    return bw;
  }

  toRaw() {
    const size = this.getSize();
    return this.toWriter(bio.write(size)).render();
  }

  fromReader(br) {
    this.name = readNameBR(br);
    this.rrtype = br.readU16BE();
    this.class = br.readU16BE();
    this.ttl = br.readU32BE();
    const rdlength = br.readU16BE();
    this.data = br.readBytes(rdlength);
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

exports.types = types;
exports.classes = classes;
exports.rcodes = rcodes;
exports.opcodes = opcodes;
exports.flags = flags;
exports.Message = Message;
exports.Question = Question;
exports.Record = Record;
