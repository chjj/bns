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

/*
 * Constants
 */

const DUMMY = Buffer.alloc(0);
const DUMMY2 = Buffer.alloc(2);
const DUMMY4 = Buffer.alloc(4);
const DUMMY6 = Buffer.alloc(6);
const DUMMY8 = Buffer.alloc(8);
const DUMMY16 = Buffer.alloc(16);

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
  WKS: 11,
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
  NSAP: 22,
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
  A6: 38,
  DNAME: 39,
  // SINK: 40,
  OPT: 41,
  APL: 42,
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

const codes = {
  // Message Response Codes
  // https://www.iana.org/assignments/dns-parameters/dns-parameters.xhtml
  NOERROR: 0,
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

/**
 * Message
 */

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
    this.code = 0; // rcode
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

    if (this.code)
      bits |= this.code & 0x0f;

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
    this.code = bits & 0x0f;

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

/**
 * Question
 */

class Question {
  constructor() {
    this.name = '';
    this.type = 0; // qtype
    this.class = 0; // qclass
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
    return this.toWriter(bio.write(size)).render();
  }

  fromReader(br) {
    this.name = readNameBR(br);

    if (br.left() === 0)
      return this;

    this.type = br.readU16BE();

    if (br.left() === 0)
      return this;

    this.class = br.readU16BE();

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

/**
 * Record
 */

class Record {
  constructor() {
    this.name = '';
    this.type = 0; // rrtype
    this.class = 0;
    this.ttl = 0;
    this.data = new ANYRecord(); // rdata
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
    bw.writeBytes(this.data.toRaw());
    return bw;
  }

  toRaw() {
    const size = this.getSize();
    return this.toWriter(bio.write(size)).render();
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
  getSize() {
    return 0;
  }

  toWriter(bw) {
    return bw;
  }

  fromReader(br) {
    return this;
  }

  toRaw() {
    const size = this.getSize();
    const bw = bio.write(size);
    this.toWriter(bw)
    return bw.render();
  }

  fromRaw(data) {
    const br = bio.read(data);
    return this.fromReader(br);
  }

  static fromReader(br) {
    return new this().fromReader(br);
  }

  static fromRaw(data) {
    return new this().fromRaw(data);
  }
}

/**
 * ANY
 */

class ANYRecord extends RecordData {
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
    this.data = br.data;
    return this;
  }
}

/**
 * CNAME
 */

class CNAMERecord extends RecordData {
  constructor() {
    super();
    this.target = '';
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
 * HINFO
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
 * MB
 */

class MBRecord extends RecordData {
  constructor() {
    super();
    this.mb = '';
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
 * MG
 */

class MGRecord extends RecordData {
  constructor() {
    super();
    this.mg = '';
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
 * MINFO
 */

class MINFORecord extends RecordData {
  constructor() {
    super();
    this.rmail = '';
    this.email = '';
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
 * MR
 */

class MRRecord extends RecordData {
  constructor() {
    super();
    this.mr = '';
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
 * MF
 */

class MFRecord extends RecordData {
  constructor() {
    super();
    this.mf = '';
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
 * MD
 */

class MDRecord extends RecordData {
  constructor() {
    super();
    this.md = '';
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
 * MX
 */

class MXRecord extends RecordData {
  constructor() {
    super();
    this.preference = 0;
    this.mx = '';
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
 * AFSDB
 */

class AFSDBRecord extends RecordData {
  constructor() {
    super();
    this.subtype = 0;
    this.hostname = '';
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
 * X25
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
 * RT
 */

class RTRecord extends RecordData {
  constructor() {
    super();
    this.preference = 0;
    this.host = '';
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
 * NS
 */

class NSRecord extends RecordData {
  constructor() {
    super();
    this.ns = '';
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
 * PTR
 */

class PTRRecord extends RecordData {
  constructor() {
    super();
    this.ptr = '';
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
 * RP
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
 * SOARecord
 */

class SOARecord extends RecordData {
  constructor() {
    super();
    this.ns = '';
    this.mbox = '';
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
 * TXT
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
 * SPF
 */

class SPFRecord extends TXTRecord {
  constructor() {
    super();
  }
}

/**
 * AVC
 */

class AVCRecord extends TXTRecord {
  constructor() {
    super();
  }
}

/**
 * SRVRecord
 */

class SRVRecord extends RecordData {
  constructor() {
    super();
    this.priority = 0;
    this.weight = 0;
    this.port = 0;
    this.target = '';
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
 * NAPTRRecord
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
 * CERTRecord
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
 * DNAME
 */

class DNAMERecord extends CNAMERecord {
  constructor() {
    super();
  }
}

/**
 * ARecord
 */

class ARecord extends RecordData {
  constructor() {
    super();
    this.ip4 = DUMMY4;
  }

  getSize() {
    return 4;
  }

  toWriter(bw) {
    bw.writeBytes(this.ip4);
    return bw;
  }

  fromReader(br) {
    this.ip4 = br.readBytes(4);
    return this;
  }
}

/**
 * AAAARecord
 */

class AAAARecord extends RecordData {
  constructor() {
    super();
    this.ip6 = DUMMY16;
  }

  getSize() {
    return 16;
  }

  toWriter(bw) {
    bw.writeBytes(this.ip6);
    return bw;
  }

  fromReader(br) {
    this.ip6 = br.readBytes(16);
    return this;
  }
}

/**
 * PXRecord
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
 * GPOSRecord
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
 * LOCRecord
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
 * SIGRecord
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
    this.signerName = '';
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
}

/**
 * RRSIGRecord
 */

class RRSIGRecord extends SIGRecord {
  constructor() {
    super();
  }
}

/**
 * NSECRecord
 */

class NSECRecord extends RecordData {
  constructor() {
    super();
    this.nextDomain = '';
    this.typeBitmap = DUMMY2;
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
 * DSRecord
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
}

/**
 * DLVRecord
 */

class DLVRecord extends DSRecord {
  constructor() {
    super();
  }
}


/**
 * CDSRecord
 */

class CDSRecord extends DSRecord {
  constructor() {
    super();
  }
}

/**
 * KXRecord
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
 * TARecord
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
 * TALINKRecord
 */

class TALINKRecord extends RecordData {
  constructor() {
    super();
    this.prevName = '';
    this.nextName = '';
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
 * SSHFPRecord
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
 * KEY
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
}

/**
 * DNSKEYRecord
 */

class DNSKEYRecord extends KEYRecord {
  constructor() {
    super();
  }
}

/**
 * CDNSKEYRecord
 */

class CDNSKEYRecord extends KEYRecord {
  constructor() {
    super();
  }
}

/**
 * RKEYRecord
 */

class RKEYRecord extends KEYRecord {
  constructor() {
    super();
  }
}

/**
 * NSAPPTRRecord
 */

class NSAPPTRRecord extends PTRRecord {
  constructor() {
    super();
  }
}

/**
 * NSEC3
 */

class NSEC3Record extends RecordData {
  constructor() {
    super();
    this.hash = 0;
    this.flags = 0;
    this.iterations = 0;
    this.salt = DUMMY;
    this.nextDomain = DUMMY;
    this.typeBitmap = DUMMY2;
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
}

/**
 * NSEC3PARAM
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
 * TKEY
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
 * RFC3597Record
 */

class RFC3597Record extends ANYRecord {
  constructor() {
    super();
    this.rdata = DUMMY;
  }

  getSize() {
    return this.rdata.length;
  }

  toWriter(bw) {
    bw.writeBytes(this.rdata);
    return bw;
  }

  fromReader(br) {
    this.rdata = br.readBytes(br.left());
    return this;
  }
}

/**
 * URIRecord
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
 * DHCIDRecord
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
 * TLSARecord
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
 * SMIMEARecord
 */

class SMIMEARecord extends TLSARecord {
  constructor() {
    super();
  }
}

/**
 * HIPRecord
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
 * NINFO
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
 * NID
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
 */

class L32Record extends RecordData {
  constructor() {
    super();
    this.preference = 0;
    this.locator32 = DUMMY4;
  }

  getSize() {
    return 6;
  }

  toWriter(bw) {
    bw.writeU16BE(this.preference);
    bw.writeBytes(this.locator32);
    return bw;
  }

  fromReader(br) {
    this.preference = br.readU16BE();
    this.locator32 = br.readBytes(4);
    return this;
  }
}

/**
 * L64Record
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
 * LPRecord
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
 * EUI48
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
 * EUI64
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
 * CAA
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
 * UID
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
 * GID
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
 * UINFO
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
 * EID
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
 * NIMLOCRecord
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
 * OPENPGPKEYRecord
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
 * CSYNCRecord
 */

class CSYNCRecord extends RecordData {
  constructor() {
    super();
    this.serial = 0;
    this.flags = 0;
    this.typeBitmap = DUMMY2;
  }

  getSize() {
    return 6 + this.typeBitmap.length;
  }

  toWriter(bw) {
    bw.writeU32BE(this.serial);
    bw.writeU16BE(this.flags);
    bw.writeBytes(this.publicKey);
    return bw;
  }

  fromReader(br) {
    this.serial = br.readU32BE();
    this.flags = br.readU16BE();
    this.publicKey = br.readBytes(br.left());
    return this;
  }
}

/**
 * TSIGRecord
 * https://tools.ietf.org/html/rfc2845
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
 * ISDNRecord
 * https://tools.ietf.org/html/rfc1183
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
 * NULL
 * https://tools.ietf.org/html/rfc1035
 */

class NULLRecord extends ANYRecord {
  constructor() {
    super();
  }
}

/**
 * OPTRecord
 * https://tools.ietf.org/html/rfc6891#section-6.1
 */

class OPTRecord extends RecordData {
  constructor() {
    super();
    this.code = 0;
    this.data = DUMMY;
  }

  getSize() {
    return 4 + this.data.length;
  }

  toWriter(bw) {
    bw.writeU16BE(this.code);
    bw.writeU16BE(this.data.length);
    bw.writeBytes(this.data);
    return bw;
  }

  fromReader(br) {
    this.code = br.readU16BE();
    this.data = br.readBytes(br.readU16BE());
    return this;
  }
}

/**
 * APLRecord
 * https://tools.ietf.org/html/rfc3123
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
 * NXTRecord
 * https://tools.ietf.org/html/rfc2065#section-5.2
 */

class NXTRecord extends RecordData {
  constructor() {
    super();
    this.nextDomain = '';
    this.typeBitmap = DUMMY2;
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
 * ATMARecord
 * http://www.broadband-forum.org/ftp/pub/approved-specs/af-dans-0152.000.pdf
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
 * UNSPEC
 */

class UNSPECRecord extends ANYRecord {
  constructor() {
    super();
  }
}

/**
 * WKSRecord
 * https://tools.ietf.org/html/rfc883
 */

class WKSRecord extends RecordData {
  constructor() {
    super();
    this.address = DUMMY4;
    this.protocol = 0;
    this.bitmap = DUMMY2;
  }

  getSize() {
    return 5 + this.bitmap.length;
  }

  toWriter(bw) {
    bw.writeBytes(this.address);
    bw.writeU8(this.protocol);
    bw.writeBytes(this.bitmap);
    return bw;
  }

  fromReader(br) {
    this.address = br.readBytes(4);
    this.protocol = br.readU8();
    this.bitmap = br.readBytes(br.left());
    return this;
  }
}

/**
 * IPSECKEYRecord
 * https://tools.ietf.org/html/rfc4025
 */

class IPSECKEYRecord extends RecordData {
  constructor() {
    super();
    this.precedence = 0;
    this.gatewayType = 0;
    this.algorithm = 0;
    this.ip4 = DUMMY4;
    this.ip6 = DUMMY16;
    this.domain = '';
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
        size += sizeName(this.domain);
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
      case 1:
        assert(this.ip4.length === 4);
        bw.writeBytes(this.ip4);
        break;
      case 2:
        assert(this.ip6.length === 16);
        bw.writeBytes(this.ip6);
        break;
      case 3:
        writeNameBW(bw, this.domain);
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
        this.ip4 = br.readBytes(4);
        break;
      case 2:
        this.ip6 = br.readBytes(16);
        break;
      case 3:
        this.domain = readNameBR(br);
        break;
      default:
        throw new Error('Unknown gateway type.');
    }

    this.publicKey = br.readBytes(br.left());

    return this;
  }
}

/**
 * NSAPRecord
 * https://tools.ietf.org/html/rfc1706
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
 * A6Record
 * https://tools.ietf.org/html/rfc2874#section-3.1.1
 */

class A6Record extends RecordData {
  constructor() {
    super();
    this.address = DUMMY16;
    this.prefix = '';
  }

  getSize() {
    return 17 + this.prefix.length;
  }

  toWriter(bw) {
    bw.writeU8(this.prefix.length);
    bw.writeBytes(this.address);
    bw.writeString(this.prefix, 'ascii');
    return bw;
  }

  fromReader(br) {
    const prefixLen = br.readU8();
    this.address = br.readBytes(16);
    this.prefix = br.readString('ascii', prefixLen);
    return this;
  }
}

/*
 * Decode
 */

function decode(type, data) {
  switch (type) {
    case types.NONE:
      return ANYRecord.fromRaw(data);
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
    case types.TKEY:
      return TKEYRecord.fromRaw(data);
    case types.TSIG:
      return TSIGRecord.fromRaw(data);
    default:
      return ANYRecord.fromRaw(data);
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

  let ret = null;

  switch (type) {
    case types.NONE:
      ret = ANYRecord.fromReader(cbr);
      break;
    case types.A:
      ret = ARecord.fromReader(cbr);
      break;
    case types.NS:
      ret = NSRecord.fromReader(cbr);
      break;
    case types.MD:
      ret = MDRecord.fromReader(cbr);
      break;
    case types.MF:
      ret = MFRecord.fromReader(cbr);
      break;
    case types.CNAME:
      ret = CNAMERecord.fromReader(cbr);
      break;
    case types.SOA:
      ret = SOARecord.fromReader(cbr);
      break;
    case types.MB:
      ret = MBRecord.fromReader(cbr);
      break;
    case types.MG:
      ret = MGRecord.fromReader(cbr);
      break;
    case types.MR:
      ret = MRRecord.fromReader(cbr);
      break;
    case types.NULL:
      ret = NULLRecord.fromReader(cbr);
      break;
    case types.WKS:
      ret = WKSRecord.fromReader(cbr);
      break;
    case types.PTR:
      ret = PTRRecord.fromReader(cbr);
      break;
    case types.HINFO:
      ret = HINFORecord.fromReader(cbr);
      break;
    case types.MINFO:
      ret = MINFORecord.fromReader(cbr);
      break;
    case types.MX:
      ret = MXRecord.fromReader(cbr);
      break;
    case types.TXT:
      ret = TXTRecord.fromReader(cbr);
      break;
    case types.RP:
      ret = RPRecord.fromReader(cbr);
      break;
    case types.AFSDB:
      ret = AFSDBRecord.fromReader(cbr);
      break;
    case types.X25:
      ret = X25Record.fromReader(cbr);
      break;
    case types.ISDN:
      ret = ISDNRecord.fromReader(cbr);
      break;
    case types.RT:
      ret = RTRecord.fromReader(cbr);
      break;
    case types.NSAP:
      ret = NSAPRecord.fromReader(cbr);
      break;
    case types.NSAPPTR:
      ret = NSAPPTRRecord.fromReader(cbr);
      break;
    case types.SIG:
      ret = SIGRecord.fromReader(cbr);
      break;
    case types.KEY:
      ret = KEYRecord.fromReader(cbr);
      break;
    case types.PX:
      ret = PXRecord.fromReader(cbr);
      break;
    case types.GPOS:
      ret = GPOSRecord.fromReader(cbr);
      break;
    case types.AAAA:
      ret = AAAARecord.fromReader(cbr);
      break;
    case types.LOC:
      ret = LOCRecord.fromReader(cbr);
      break;
    case types.NXT:
      ret = NXTRecord.fromReader(cbr);
      break;
    case types.EID:
      ret = EIDRecord.fromReader(cbr);
      break;
    case types.NIMLOC:
      ret = NIMLOCRecord.fromReader(cbr);
      break;
    case types.SRV:
      ret = SRVRecord.fromReader(cbr);
      break;
    case types.ATMA:
      ret = ATMARecord.fromReader(cbr);
      break;
    case types.NAPTR:
      ret = NAPTRRecord.fromReader(cbr);
      break;
    case types.KX:
      ret = KXRecord.fromReader(cbr);
      break;
    case types.CERT:
      ret = CERTRecord.fromReader(cbr);
      break;
    case types.A6:
      ret = A6Record.fromReader(cbr);
      break;
    case types.DNAME:
      ret = DNAMERecord.fromReader(cbr);
      break;
    case types.OPT:
      ret = OPTRecord.fromReader(cbr);
      break;
    case types.APL:
      ret = APLRecord.fromReader(cbr);
      break;
    case types.DS:
      ret = DSRecord.fromReader(cbr);
      break;
    case types.SSHFP:
      ret = SSHFPRecord.fromReader(cbr);
      break;
    case types.IPSECKEY:
      ret = IPSECKEYRecord.fromReader(cbr);
      break;
    case types.RRSIG:
      ret = RRSIGRecord.fromReader(cbr);
      break;
    case types.NSEC:
      ret = NSECRecord.fromReader(cbr);
      break;
    case types.DNSKEY:
      ret = DNSKEYRecord.fromReader(cbr);
      break;
    case types.DHCID:
      ret = DHCIDRecord.fromReader(cbr);
      break;
    case types.NSEC3:
      ret = NSEC3Record.fromReader(cbr);
      break;
    case types.NSEC3PARAM:
      ret = NSEC3PARAMRecord.fromReader(cbr);
      break;
    case types.TLSA:
      ret = TLSARecord.fromReader(cbr);
      break;
    case types.SMIMEA:
      ret = SMIMEARecord.fromReader(cbr);
      break;
    case types.HIP:
      ret = HIPRecord.fromReader(cbr);
      break;
    case types.NINFO:
      ret = NINFORecord.fromReader(cbr);
      break;
    case types.RKEY:
      ret = RKEYRecord.fromReader(cbr);
      break;
    case types.TALINK:
      ret = TALINKRecord.fromReader(cbr);
      break;
    case types.CDS:
      ret = CDSRecord.fromReader(cbr);
      break;
    case types.CDNSKEY:
      ret = CDNSKEYRecord.fromReader(cbr);
      break;
    case types.OPENPGPKEY:
      ret = OPENPGPKEYRecord.fromReader(cbr);
      break;
    case types.CSYNC:
      ret = CSYNCRecord.fromReader(cbr);
      break;
    case types.SPF:
      ret = SPFRecord.fromReader(cbr);
      break;
    case types.UINFO:
      ret = UINFORecord.fromReader(cbr);
      break;
    case types.UID:
      ret = UIDRecord.fromReader(cbr);
      break;
    case types.GID:
      ret = GIDRecord.fromReader(cbr);
      break;
    case types.UNSPEC:
      ret = UNSPECRecord.fromReader(cbr);
      break;
    case types.NID:
      ret = NIDRecord.fromReader(cbr);
      break;
    case types.L32:
      ret = L32Record.fromReader(cbr);
      break;
    case types.L64:
      ret = L64Record.fromReader(cbr);
      break;
    case types.LP:
      ret = LPRecord.fromReader(cbr);
      break;
    case types.EUI48:
      ret = EUI48Record.fromReader(cbr);
      break;
    case types.EUI64:
      ret = EUI64Record.fromReader(cbr);
      break;
    case types.URI:
      ret = URIRecord.fromReader(cbr);
      break;
    case types.CAA:
      ret = CAARecord.fromReader(cbr);
      break;
    case types.AVC:
      ret = AVCRecord.fromReader(cbr);
      break;
    case types.TKEY:
      ret = TKEYRecord.fromReader(cbr);
      break;
    case types.TSIG:
      ret = TSIGRecord.fromReader(cbr);
      break;
    default:
      ret = ANYRecord.fromReader(cbr);
      break;
  }

  br.offset = cbr.offset;

  return ret;
}


/*
 * Expose
 */

exports.types = types;
exports.classes = classes;
exports.codes = codes;
exports.opcodes = opcodes;
exports.flags = flags;
exports.Message = Message;
exports.Question = Question;
exports.Record = Record;

exports.ANYRecord = ANYRecord;
exports.CNAMERecord = CNAMERecord;
exports.HINFORecord = HINFORecord;
exports.MBRecord = MBRecord;
exports.MGRecord = MGRecord;
exports.MINFORecord = MINFORecord;
exports.MRRecord = MRRecord;
exports.MFRecord = MFRecord;
exports.MDRecord = MDRecord;
exports.MXRecord = MXRecord;
exports.AFSDBRecord = AFSDBRecord;
exports.X25Record = X25Record;
exports.RTRecord = RTRecord;
exports.NSRecord = NSRecord;
exports.PTRRecord = PTRRecord;
exports.RPRecord = RPRecord;
exports.SOARecord = SOARecord;
exports.TXTRecord = TXTRecord;
exports.SPFRecord = SPFRecord;
exports.AVCRecord = AVCRecord;
exports.SRVRecord = SRVRecord;
exports.NAPTRRecord = NAPTRRecord;
exports.CERTRecord = CERTRecord;
exports.A6Record = A6Record;
exports.DNAMERecord = DNAMERecord;
exports.ARecord = ARecord;
exports.AAAARecord = AAAARecord;
exports.PXRecord = PXRecord;
exports.GPOSRecord = GPOSRecord;
exports.LOCRecord = LOCRecord;
exports.SIGRecord = SIGRecord;
exports.RRSIGRecord = RRSIGRecord;
exports.NSECRecord = NSECRecord;
exports.DSRecord = DSRecord;
exports.DLVRecord = DLVRecord;
exports.CDSRecord = CDSRecord;
exports.KXRecord = KXRecord;
exports.TARecord = TARecord;
exports.TALINKRecord = TALINKRecord;
exports.SSHFPRecord = SSHFPRecord;
exports.IPSECKEYRecord = IPSECKEYRecord;
exports.KEYRecord = KEYRecord;
exports.DNSKEYRecord = DNSKEYRecord;
exports.CDNSKEYRecord = CDNSKEYRecord;
exports.RKEYRecord = RKEYRecord;
exports.NSAPRecord = NSAPRecord;
exports.NSAPPTRRecord = NSAPPTRRecord;
exports.NSEC3Record = NSEC3Record;
exports.NSEC3PARAMRecord = NSEC3PARAMRecord;
exports.TKEYRecord = TKEYRecord;
exports.RFC3597Record = RFC3597Record;
exports.URIRecord = URIRecord;
exports.DHCIDRecord = DHCIDRecord;
exports.SMIMEARecord = SMIMEARecord;
exports.HIPRecord = HIPRecord;
exports.NINFORecord = NINFORecord;
exports.NIDRecord = NIDRecord;
exports.L32Record = L32Record;
exports.L64Record = L64Record;
exports.LPRecord = LPRecord;
exports.EUI48Record = EUI48Record;
exports.EUI64Record = EUI64Record;
exports.CAARecord = CAARecord;
exports.UIDRecord = UIDRecord;
exports.GIDRecord = GIDRecord;
exports.UINFORecord = UINFORecord;
exports.EIDRecord = EIDRecord;
exports.NIMLOCRecord = NIMLOCRecord;
exports.OPENPGPKEYRecord = OPENPGPKEYRecord;
exports.CSYNCRecord = CSYNCRecord;
exports.TSIGRecord = TSIGRecord;
exports.ISDNRecord = ISDNRecord;
exports.NULLRecord = NULLRecord;
exports.WKSRecord = WKSRecord;
exports.OPTRecord = OPTRecord;
exports.APLRecord = APLRecord;
exports.NXTRecord = NXTRecord;
exports.ATMARecord = ATMARecord;
exports.UNSPECRecord = UNSPECRecord;

exports.decode = decode;
exports.read = read;
