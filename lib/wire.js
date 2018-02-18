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
const constants = require('./constants');
const schema = require('./schema');
const {Struct} = bio;

const {
  sizeName,
  writeNameBW,
  readNameBR,
  toBitmap,
  fromBitmap,
  hasType
} = encoding;

const {
  opcodes,
  opcodesByVal,
  flags,
  flagsByVal,
  codes,
  codesByVal,
  types,
  typesByVal,
  classes,
  classesByVal,
  short,
  shortByVal,
  eflags,
  eflagsByVal,
  options,
  optionsByVal
} = constants;

/*
 * Constants
 */

const DUMMY = Buffer.alloc(0);
const DUMMY6 = Buffer.alloc(6);
const DUMMY8 = Buffer.alloc(8);
const DUMMY32 = Buffer.alloc(32);

/**
 * Record Classes
 * @const {Object}
 */

let records = {};

/**
 * Record Classes By Value
 * @const {Object}
 */

let recordsByVal = {};

/**
 * EDNS0 Option Classes
 * @const {Object}
 */

let opts = {};

/**
 * EDNS0 Option Classes By Value
 * @const {Object}
 */

let optsByVal = {};

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
    this.question = msg.question.slice();
    this.answer = msg.answer.slice();
    this.authority = msg.authority.slice();
    this.additional = msg.additional.slice();
    return this;
  }

  clone() {
    const msg = new this.constructor();
    return msg.inject(this);
  }

  deepClone() {
    const msg = new this.constructor();
    return msg.fromRaw(this.toRaw());
  }

  sections() {
    return [
      this.answer,
      this.authority,
      this.additional
    ];
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
        if (rr.type === types.OPT)
          continue;

        if (ttl === -1 || rr.ttl < ttl)
          ttl = rr.ttl;

        if (rr.type === types.RRSIG) {
          const e = rr.data.expiration;
          const t = e - util.now();

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

  toString() {
    const opcode = opcodesByVal[this.opcode] || 'UNKNOWN';
    const status = codesByVal[this.code] || 'UNKNOWN';
    const id = String(this.id);
    const flags = [];

    if (this.qr)
      flags.push('qr');

    if (this.aa)
      flags.push('aa');

    if (this.tc)
      flags.push('tc');

    if (this.rd)
      flags.push('rd');

    if (this.ra)
      flags.push('ra');

    if (this.z)
      flags.push('z');

    if (this.ad)
      flags.push('ad');

    if (this.cd)
      flags.push('cd');

    let str = '';

    str += ';; ->>HEADER<<-';
    str += ` opcode: ${opcode}, status: ${status}, id: ${id}\n`;
    str += `;; flags: ${flags.join(' ')},`;
    str += ` QUERY: ${this.question.length},`;
    str += ` ANSWER: ${this.answer.length},`;
    str += ` AUTHORITY: ${this.authority.length},`;
    str += ` ADDITIONAL: ${this.additional.length}\n`;

    const edns = this.getEDNS0();

    if (edns) {
      const version = edns.version;
      const flags = edns.dok ? 'do' : '';
      const udp = edns.usize;

      str += '\n';
      str += ';; OPT PSEUDOSECTION:\n';
      str += `; EDNS: version: ${version}, flags: ${flags}, udp: ${udp}\n`;
    }

    if (this.question.length > 0) {
      str += '\n';
      str += ';; QUESTION SECTION:\n';

      for (const qs of this.question)
        str += `; ${qs.toString()}\n`;
    }

    if (this.answer.length > 0) {
      str += '\n';
      str += ';; ANSWER SECTION:\n';

      for (const rr of this.answer)
        str += `${rr.toString()}\n`;
    }

    if (this.authority.length > 0) {
      str += '\n';
      str += ';; AUTHORITY SECTION:\n';

      for (const rr of this.authority)
        str += `${rr.toString()}\n`;
    }

    if (this.additional.length > 0) {
      str += '\n';
      str += ';; ADDITIONAL SECTION:\n';

      for (const rr of this.additional)
        str += `${rr.toString()}\n`;
    }

    return str.slice(0, -1);
  }

  fromString(str) {
    return this;
  }

  static fromString(str) {
    return new this().fromString(str);
  }

  toJSON() {
    const opcode = opcodesByVal[this.opcode] || 'UNKNOWN';
    const code = codesByVal[this.code] || 'UNKNOWN';

    return {
      id: this.id,
      opcode: opcode,
      code: code,
      qr: this.qr,
      aa: this.aa,
      tc: this.tc,
      rd: this.rd,
      ra: this.ra,
      z: this.z,
      ad: this.ad,
      cd: this.cd,
      question: this.question.map(qs => qs.toJSON()),
      answer: this.answer.map(rr => rr.toJSON()),
      authority: this.authority.map(rr => rr.toJSON()),
      additional: this.additional.map(rr => rr.toJSON())
    };
  }

  fromJSON(json) {
    assert(json && typeof json === 'object');
    assert((json.id & 0xffff) === json.id);
    assert(opcodes[json.opcode] != null);
    assert(codes[json.code] != null);
    assert(typeof json.qr === 'boolean');
    assert(typeof json.aa === 'boolean');
    assert(typeof json.tc === 'boolean');
    assert(typeof json.rd === 'boolean');
    assert(typeof json.ra === 'boolean');
    assert(typeof json.z === 'boolean');
    assert(typeof json.ad === 'boolean');
    assert(typeof json.cd === 'boolean');
    assert(Array.isArray(json.question));
    assert(Array.isArray(json.answer));
    assert(Array.isArray(json.authority));
    assert(Array.isArray(json.additional));

    this.id = json.id;
    this.opcode = opcodes[json.opcode];
    this.code = codes[json.code];
    this.qr = json.qr;
    this.aa = json.aa;
    this.tc = json.tc;
    this.rd = json.rd;
    this.ra = json.ra;
    this.z = json.z;
    this.ad = json.ad;
    this.cd = json.cd;

    for (const qs of json.question)
      this.question.push(Question.fromJSON(qs));

    for (const rr of json.answer)
      this.answer.push(Record.fromJSON(rr));

    for (const rr of json.authority)
      this.authority.push(Record.fromJSON(rr));

    for (const rr of json.additional)
      this.additional.push(Record.fromJSON(rr));

    return this;
  }

  static fromJSON(json) {
    return new this().fromJSON(json);
  }

  inspect() {
    return this.toJSON();
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

  toString() {
    const name = this.name;
    const cls = shortByVal[this.class] || 'UN';
    const type = typesByVal[this.type] || 'UNKNOWN';
    return `${name} ${cls} ${type}`;
  }

  fromString(str) {
    const parts = str.trim().split(/\s+/);

    assert(parts.length === 3);

    const name = parts[0];
    assert(util.isName(name));

    const cls = short[parts[1]];
    assert(cls != null);

    const type = types[parts[2]];
    assert(type != null);

    this.name = name;
    this.class = cls;
    this.type = type;

    return this;
  }

  static fromString(str) {
    return new this().fromString(str);
  }

  toJSON() {
    const name = this.name;
    const cls = classesByVal[this.class] || 'UNKNOWN';
    const type = typesByVal[this.type] || 'UNKNOWN';

    return {
      name: name,
      class: cls,
      type: type
    };
  }

  fromJSON(json) {
    assert(json && typeof json === 'object');
    assert(typeof json.name === 'string');
    assert(util.isName(json.name));
    assert(classes[json.class] != null);
    assert(types[json.type] != null);

    this.name = json.name;
    this.class = classes[json.class];
    this.type = types[json.type];

    return this;
  }

  static fromJSON(json) {
    return new this().fromJSON(json);
  }

  inspect() {
    return this.toJSON();
  }
}

/**
 * Record
 */

class Record {
  constructor() {
    this.name = '.';
    this.type = types.UNKNOWN;
    this.class = classes.INET;
    this.ttl = 0;
    this.data = new UNKNOWNRecord();
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

  deepClone() {
    const r = new this.constructor();
    return r.fromRaw(this.toRaw());
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

  toString() {
    const name = this.name;
    const ttl = this.ttl;
    const cls = shortByVal[this.class] || 'UN';
    const type = typesByVal[this.type] || 'UNKNOWN';
    const body = this.data.toString();

    return `${name} ${ttl} ${cls} ${type} ${body}`;
  }

  fromString(str) {
    const parts = str.trim().split(/\s+/);

    assert(parts.length >= 4);

    const name = parts[0];
    assert(util.isName(name));

    const ttl = parseInt(parts[1], 10);
    assert((ttl >>> 0) === ttl);

    const cls = short[parts[2]];
    assert(cls != null);

    const type = types[parts[3]];
    assert(type != null);

    const RD = recordsByVal[type];
    assert(RD);

    const body = parts.slice(4).join(' ');

    this.name = name;
    this.ttl = ttl;
    this.class = cls;
    this.type = type;
    this.data = RD.fromString(body);

    return this;
  }

  static fromString(str) {
    return new this().fromString(str);
  }

  toJSON() {
    const name = this.name;
    const ttl = this.ttl;
    const cls = classesByVal[this.class] || 'UNKNOWN';
    const type = typesByVal[this.type] || 'UNKNOWN';

    return {
      name: name,
      ttl: ttl,
      class: cls,
      type: type,
      data: this.data.toJSON()
    };
  }

  fromJSON(json) {
    assert(json && typeof json === 'object');
    assert(typeof json.name === 'string');
    assert((json.ttl >>> 0) === json.ttl);
    assert(util.isName(json.name));
    assert(classes[json.class] != null);
    assert(types[json.type] != null);
    assert(json.data && typeof json.data === 'object');

    this.name = json.name;
    this.ttl = json.ttl;
    this.class = classes[json.class];
    this.type = types[json.type];

    const RD = recordsByVal[this.type];
    assert(RD);

    this.data = RD.fromJSON(json.data);

    return this;
  }

  static fromJSON(json) {
    return new this().fromJSON(json);
  }

  inspect() {
    return this.toJSON();
  }
}

/**
 * RecordData
 */

class RecordData extends Struct {
  constructor() {
    super();
  }

  get type() {
    return types.UNKNOWN;
  }

  toString() {
    return schema.toString(this, schema.schemasByVal[this.type]);
  }

  fromString(str) {
    return schema.fromString(this, schema.schemasByVal[this.type], str);
  }

  static fromString(str) {
    return new this().fromString(str);
  }

  toJSON() {
    return schema.toJSON(this, schema.schemasByVal[this.type]);
  }

  fromJSON(json) {
    return schema.fromJSON(this, schema.schemasByVal[this.type], json);
  }

  static fromJSON(json) {
    return new this().fromJSON(json);
  }

  inspect() {
    return this.toJSON();
  }
}

/**
 * UNKNOWN Record
 */

class UNKNOWNRecord extends RecordData {
  constructor() {
    super();
    this.data = DUMMY;
  }

  get type() {
    return types.UNKNOWN;
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

  get type() {
    return types.A;
  }

  getSize() {
    return 4;
  }

  toWriter(bw) {
    const ip = IP.toBuffer(this.address);
    assert(IP.isIPv4(ip));
    bw.copy(ip, 12, 16);
    return bw;
  }

  fromReader(br) {
    this.address = IP.toString(br.readBytes(4));
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

  get type() {
    return types.NS;
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

  get type() {
    return types.MD;
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

  get type() {
    return types.MF;
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

  get type() {
    return types.CNAME;
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

  get type() {
    return types.SOA;
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

  get type() {
    return types.MB;
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

  get type() {
    return types.MG;
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

  get type() {
    return types.MR;
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

  get type() {
    return types.NULL;
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

  get type() {
    return types.WKS;
  }

  getSize() {
    return 5 + this.bitmap.length;
  }

  toWriter(bw) {
    const ip = IP.toBuffer(this.address);
    assert(IP.isIPv4(ip));
    bw.copy(ip, 12, 16);
    bw.writeU8(this.protocol);
    bw.writeBytes(this.bitmap);
    return bw;
  }

  fromReader(br) {
    this.address = IP.toString(br.readBytes(4));
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

  get type() {
    return types.PTR;
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

  get type() {
    return types.HINFO;
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

  get type() {
    return types.MINFO;
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

  get type() {
    return types.MX;
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

  get type() {
    return types.TXT;
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

  get type() {
    return types.RP;
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

  get type() {
    return types.AFSDB;
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

  get type() {
    return types.X25;
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

  get type() {
    return types.ISDN;
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

  get type() {
    return types.RT;
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

  get type() {
    return types.NSAP;
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

  get type() {
    return types.NSAPPTR;
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

  get type() {
    return types.SIG;
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

  get type() {
    return types.KEY;
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

  get type() {
    return types.PX;
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

  get type() {
    return types.GPOS;
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

  get type() {
    return types.AAAA;
  }

  getSize() {
    return 16;
  }

  toWriter(bw) {
    const ip = IP.toBuffer(this.address);
    assert(!IP.isIPv4(ip));
    bw.writeBytes(ip);
    return bw;
  }

  fromReader(br) {
    this.address = IP.toString(br.readBytes(16));
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

  get type() {
    return types.LOC;
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

  get type() {
    return types.NXT;
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

  get type() {
    return types.EID;
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

  get type() {
    return types.NIMLOC;
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

  get type() {
    return types.SRV;
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

  get type() {
    return types.ATMA;
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

  get type() {
    return types.NAPTR;
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

  get type() {
    return types.KX;
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
    this.certType = 0;
    this.keyTag = 0;
    this.algorithm = 0;
    this.certificate = DUMMY;
  }

  get type() {
    return types.CERT;
  }

  getSize() {
    return 5 + this.certificate.length;
  }

  toWriter(bw) {
    bw.writeU16BE(this.certType);
    bw.writeU16BE(this.keyTag);
    bw.writeU8(this.algorithm);
    bw.writeBytes(this.certificate);
    return bw;
  }

  fromReader(br) {
    this.certType = br.readU16BE();
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

  get type() {
    return types.A6;
  }

  getSize() {
    return 17 + this.prefix.length;
  }

  toWriter(bw) {
    bw.writeU8(this.prefix.length);
    const ip = IP.toBuffer(this.address);
    assert(!IP.isIPv4(ip));
    bw.writeBytes(ip);
    bw.writeString(this.prefix, 'ascii');
    return bw;
  }

  fromReader(br) {
    const prefixLen = br.readU8();
    this.address = IP.toString(br.readBytes(16));
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

  get type() {
    return types.DNAME;
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

  get type() {
    return types.OPT;
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

  toString() {
    let str = '';

    for (const opt of this.options)
      str += `${opt.toString()} `;

    return str.slice(0, -1);
  }

  fromString(str) {
    const parts = str.trim().split(/\s+/);

    let i = 0;

    while (i < parts.length) {
      const code = options[parts[0]];
      assert(code != null);

      const sa = schema.oschemasByVal[code];
      assert(sa);

      const body = parts.slice(i, i + sa.length + 1).join(' ');

      this.options.push(Option.fromString(body));

      i += sa.length + 1;
    }

    return this;
  }

  static fromString(str) {
    return new this().fromString(str);
  }

  toJSON() {
    return {
      options: this.options.map(opt => opt.toJSON())
    };
  }

  fromJSON(json) {
    assert(json && typeof json === 'object');
    assert(Array.isArray(json.options));

    for (const opt of json.options)
      this.options.push(Option.fromJSON(qs));

    return this;
  }

  static fromJSON(json) {
    return new this().fromJSON(json);
  }

  inspect() {
    return this.toJSON();
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

  get type() {
    return types.APL;
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

  get type() {
    return types.DS;
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
    this.keyType = 0;
    this.fingerprint = DUMMY;
  }

  get type() {
    return types.SSHFP;
  }

  getSize() {
    return 2 + this.fingerprint.length;
  }

  toWriter(bw) {
    bw.writeU8(this.algorithm);
    bw.writeU8(this.keyType);
    bw.writeBytes(this.fingerprint);
    return bw;
  }

  fromReader(br) {
    this.algorithm = br.readU8();
    this.keyType = br.readU8();
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

  get type() {
    return types.IPSECKEY;
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
        const ip = IP.toBuffer(this.target);
        assert(IP.isIPv4(ip));
        bw.copy(ip, 12, 16);
        break;
      }
      case 2: {
        const ip = IP.toBuffer(this.target);
        assert(!IP.isIPv4(ip));
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
        this.target = IP.toString(br.readBytes(4));
        break;
      case 2:
        this.target = IP.toString(br.readBytes(16));
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

  get type() {
    return types.RRSIG;
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

  get type() {
    return types.NSEC;
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

  get type() {
    return types.DNSKEY;
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

  get type() {
    return types.DHCID;
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

  get type() {
    return types.NSEC3;
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

  get type() {
    return types.NSEC3PARAM;
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

  get type() {
    return types.TLSA;
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

  get type() {
    return types.SMIMEA;
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

  get type() {
    return types.HIP;
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

  get type() {
    return types.NINFO;
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

  get type() {
    return types.RKEY;
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

  get type() {
    return types.TALINK;
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

  get type() {
    return types.CDS;
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

  get type() {
    return types.CDNSKEY;
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

  get type() {
    return types.OPENPGPKEY;
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

  get type() {
    return types.CSYNC;
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

  get type() {
    return types.SPF;
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

  get type() {
    return types.UINFO;
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

  get type() {
    return types.UID;
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

  get type() {
    return types.GID;
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

  get type() {
    return types.UNSPEC;
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

  get type() {
    return types.NID;
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

  get type() {
    return types.L32;
  }

  getSize() {
    return 6;
  }

  toWriter(bw) {
    bw.writeU16BE(this.preference);
    const ip = IP.toBuffer(this.locator32);
    assert(IP.isIPv4(ip));
    bw.copy(ip, 12, 16);
    return bw;
  }

  fromReader(br) {
    this.preference = br.readU16BE();
    this.locator32 = IP.toString(br.readBytes(4));
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

  get type() {
    return types.L64;
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

  get type() {
    return types.LP;
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
    this.address = 0;
  }

  get type() {
    return types.EUI48;
  }

  getSize() {
    return 6;
  }

  toWriter(bw) {
    bw.writeU16BE((this.address / 0x100000000) >>> 0);
    bw.writeU32BE(this.address >>> 0);
    return bw;
  }

  fromReader(br) {
    this.address = br.readU16BE() * 0x100000000 + br.readU32BE();
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

  get type() {
    return types.EUI64;
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

  get type() {
    return types.URI;
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

  get type() {
    return types.CAA;
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

  get type() {
    return types.AVC;
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

  get type() {
    return types.TKEY;
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

  get type() {
    return types.TSIG;
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

  get type() {
    return types.ANY;
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

  get type() {
    return types.TA;
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

  get type() {
    return types.DLV;
  }
}

/**
 * NAMEPROOF Record
 * Name Proof Record
 */

class NAMEPROOFRecord extends RecordData {
  constructor() {
    super();
    this.exists = false;
    this.nodes = [];
    this.data = DUMMY;
  }

  get type() {
    return types.NAMEPROOF;
  }

  getSize() {
    let size = 2;

    for (const node of this.nodes)
      size += 2 + node.length;

    if (this.data)
      size += this.data.length;

    return size;
  }

  toWriter(bw) {
    const exists = this.exists ? 0x8000 : 0;

    bw.writeU16BE(exists | this.nodes.length);

    for (const node of this.nodes) {
      bw.writeU16BE(node.length);
      bw.writeBytes(node);
    }

    bw.writeBytes(this.data);

    return bw;
  }

  fromReader(br) {
    const field = br.readU16BE();

    this.exists = (field & 0x8000) !== 0;

    const count = field & 0x7fff;

    for (let i = 0; i < count; i++) {
      const size = br.readU16BE();
      this.nodes.push(br.readBytes(size));
    }

    this.data = br.readBytes(br.left());

    return this;
  }
}

/**
 * Option Field
 * @see https://tools.ietf.org/html/rfc6891#section-6.1
 */

class Option extends Struct {
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

  toString() {
    const code = optionsByVal[this.code] || 'UNKNOWN';
    const body = this.option.toString();

    return `${code} ${body}`;
  }

  fromString(str) {
    const parts = str.trim().split(/\s+/);

    assert(parts.length >= 1);

    const code = options[parts[0]];
    assert(code != null);

    const Option = optsByVal[type];
    assert(Option);

    const body = parts.slice(1).join(' ');

    this.code = code;
    this.option = Option.fromString(body);

    return this;
  }

  static fromString(str) {
    return new this().fromString(str);
  }

  toJSON() {
    const code = optionsByVal[this.code] || 'UNKNOWN';
    return {
      code: code,
      option: this.option.toJSON()
    };
  }

  fromJSON(json) {
    assert(json && typeof json === 'object');
    assert(typeof json.code === 'string');
    assert(options[json.code] != null);
    assert(json.option && typeof json.option === 'object');

    this.code = options[json.code];

    const Option = optsByVal[this.code];
    assert(Option);

    this.option = Option.fromJSON(json.option);

    return this;
  }

  static fromJSON(json) {
    return new this().fromJSON(json);
  }

  inspect() {
    return this.toJSON();
  }
}

/**
 * OptionData
 */

class OptionData extends Struct {
  constructor() {
    super();
  }

  get type() {
    return options.UNKNOWN;
  }

  toString() {
    return schema.toString(this, schema.oschemasByVal[this.code]);
  }

  fromString(str) {
    return schema.fromString(this, schema.oschemasByVal[this.code], str);
  }

  static fromString(str) {
    return new this().fromString(str);
  }

  toJSON() {
    return schema.toJSON(this, schema.oschemasByVal[this.code]);
  }

  fromJSON(json) {
    return schema.fromJSON(this, schema.oschemasByVal[this.code], json);
  }

  static fromJSON(json) {
    return new this().fromJSON(json);
  }

  inspect() {
    return this.toJSON();
  }
}

/**
 * UNKNOWN Option
 * EDNS Unknown Option
 */

class UNKNOWNOption extends OptionData {
  constructor() {
    super();
    this.data = DUMMY;
  }

  get code() {
    return options.UNKNOWN;
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

class LLQOption extends OptionData {
  constructor() {
    super();
    this.version = 0;
    this.opcode = 0;
    this.error = 0;
    this.id = DUMMY8;
    this.leaseLife = 0;
  }

  get code() {
    return options.LLQ;
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

class ULOption extends OptionData {
  constructor() {
    super();
    this.lease = 0;
  }

  get code() {
    return options.UL;
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

class NSIDOption extends OptionData {
  constructor() {
    super();
    this.nsid = DUMMY;
  }

  get code() {
    return options.NSID;
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

class DAUOption extends OptionData {
  constructor() {
    super();
    this.algCode = DUMMY;
  }

  get code() {
    return options.DAU;
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

  get code() {
    return options.DHU;
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

  get code() {
    return options.N3U;
  }
}

/**
 * SUBNET Option
 * EDNS Subnet Option
 * @see https://tools.ietf.org/html/rfc7871
 */

class SUBNETOption extends OptionData {
  constructor() {
    super();
    this.family = 1;
    this.sourceNetmask = 0;
    this.sourceScope = 0;
    this.address = '0.0.0.0';
  }

  get code() {
    return options.SUBNET;
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
        const ip = IP.toBuffer(this.address);
        assert(IP.isIPv4(ip));
        bw.copy(ip, 12, 16);
        break;
      }
      case 2: {
        const ip = IP.toBuffer(this.address);
        assert(!IP.isIPv4(ip));
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
        this.address = IP.toString(br.readBytes(4));
        break;
      case 2:
        this.address = IP.toString(br.readBytes(16));
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

class EXPIREOption extends OptionData {
  constructor() {
    super();
    this.expire = 0;
  }

  get code() {
    return options.EXPIRE;
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

class COOKIEOption extends OptionData {
  constructor() {
    super();
    this.cookie = DUMMY;
  }

  get code() {
    return options.COOKIE;
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

class TCPKEEPALIVEOption extends OptionData {
  constructor() {
    super();
    this.length = 0;
    this.timeout = 0;
  }

  get code() {
    return options.TCPKEEPALIVE;
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

class PADDINGOption extends OptionData {
  constructor() {
    super();
    this.padding = DUMMY;
  }

  get code() {
    return options.PADDING;
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
 * TRIEROOT Option
 * EDNS Trie Root Option
 */

class TRIEROOTOption extends OptionData {
  constructor() {
    super();
    this.root = DUMMY32;
  }

  get code() {
    return options.TRIEROOT;
  }

  getSize() {
    return this.root.length;
  }

  toWriter(bw) {
    bw.writeBytes(this.root);
    return bw;
  }

  fromReader(br) {
    this.root = br.readBytes(32);
    return this;
  }
}

/**
 * LOCAL Option
 * EDNS Local Option
 * @see https://tools.ietf.org/html/rfc6891
 */

class LOCALOption extends OptionData {
  constructor() {
    super();
    this.data = DUMMY;
  }

  get code() {
    return options.LOCAL;
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
 * Record Classes
 * @const {Object}
 */

records = {
  UNKNOWN: UNKNOWNRecord,
  A: ARecord,
  NS: NSRecord,
  MD: MDRecord,
  MF: MFRecord,
  CNAME: CNAMERecord,
  SOA: SOARecord,
  MB: MBRecord,
  MG: MGRecord,
  MR: MRRecord,
  NULL: NULLRecord,
  WKS: WKSRecord,
  PTR: PTRRecord,
  HINFO: HINFORecord,
  MINFO: MINFORecord,
  MX: MXRecord,
  TXT: TXTRecord,
  RP: RPRecord,
  AFSDB: AFSDBRecord,
  X25: X25Record,
  ISDN: ISDNRecord,
  RT: RTRecord,
  NSAP: NSAPRecord,
  NSAPPTR: NSAPPTRRecord,
  SIG: SIGRecord,
  KEY: KEYRecord,
  PX: PXRecord,
  GPOS: GPOSRecord,
  AAAA: AAAARecord,
  LOC: LOCRecord,
  NXT: NXTRecord,
  EID: EIDRecord,
  NIMLOC: NIMLOCRecord,
  SRV: SRVRecord,
  ATMA: ATMARecord,
  NAPTR: NAPTRRecord,
  KX: KXRecord,
  CERT: CERTRecord,
  A6: A6Record,
  DNAME: DNAMERecord,
  SINK: null,
  OPT: OPTRecord,
  APL: APLRecord,
  DS: DSRecord,
  SSHFP: SSHFPRecord,
  IPSECKEY: IPSECKEYRecord,
  RRSIG: RRSIGRecord,
  NSEC: NSECRecord,
  DNSKEY: DNSKEYRecord,
  DHCID: DHCIDRecord,
  NSEC3: NSEC3Record,
  NSEC3PARAM: NSEC3PARAMRecord,
  TLSA: TLSARecord,
  SMIMEA: SMIMEARecord,
  HIP: HIPRecord,
  NINFO: NINFORecord,
  RKEY: RKEYRecord,
  TALINK: TALINKRecord,
  CDS: CDSRecord,
  CDNSKEY: CDNSKEYRecord,
  OPENPGPKEY: OPENPGPKEYRecord,
  CSYNC: CSYNCRecord,
  SPF: SPFRecord,
  UINFO: UINFORecord,
  UID: UIDRecord,
  GID: GIDRecord,
  UNSPEC: UNSPECRecord,
  NID: NIDRecord,
  L32: L32Record,
  L64: L64Record,
  LP: LPRecord,
  EUI48: EUI48Record,
  EUI64: EUI64Record,
  URI: URIRecord,
  CAA: CAARecord,
  AVC: AVCRecord,
  TKEY: TKEYRecord,
  TSIG: TSIGRecord,
  IXFR: null,
  AXFR: null,
  MAILB: null,
  MAILA: null,
  ANY: ANYRecord,
  TA: TARecord,
  DLV: DLVRecord,
  NAMEPROOF: NAMEPROOFRecord,
  RESERVED: null
};

/**
 * Record Classes By Value
 * @const {Object}
 */

recordsByVal = {
  [types.UNKNOWN]: UNKNOWNRecord,
  [types.A]: ARecord,
  [types.NS]: NSRecord,
  [types.MD]: MDRecord,
  [types.MF]: MFRecord,
  [types.CNAME]: CNAMERecord,
  [types.SOA]: SOARecord,
  [types.MB]: MBRecord,
  [types.MG]: MGRecord,
  [types.MR]: MRRecord,
  [types.NULL]: NULLRecord,
  [types.WKS]: WKSRecord,
  [types.PTR]: PTRRecord,
  [types.HINFO]: HINFORecord,
  [types.MINFO]: MINFORecord,
  [types.MX]: MXRecord,
  [types.TXT]: TXTRecord,
  [types.RP]: RPRecord,
  [types.AFSDB]: AFSDBRecord,
  [types.X25]: X25Record,
  [types.ISDN]: ISDNRecord,
  [types.RT]: RTRecord,
  [types.NSAP]: NSAPRecord,
  [types.NSAPPTR]: NSAPPTRRecord,
  [types.SIG]: SIGRecord,
  [types.KEY]: KEYRecord,
  [types.PX]: PXRecord,
  [types.GPOS]: GPOSRecord,
  [types.AAAA]: AAAARecord,
  [types.LOC]: LOCRecord,
  [types.NXT]: NXTRecord,
  [types.EID]: EIDRecord,
  [types.NIMLOC]: NIMLOCRecord,
  [types.SRV]: SRVRecord,
  [types.ATMA]: ATMARecord,
  [types.NAPTR]: NAPTRRecord,
  [types.KX]: KXRecord,
  [types.CERT]: CERTRecord,
  [types.A6]: A6Record,
  [types.DNAME]: DNAMERecord,
  [types.SINK]: null,
  [types.OPT]: OPTRecord,
  [types.APL]: APLRecord,
  [types.DS]: DSRecord,
  [types.SSHFP]: SSHFPRecord,
  [types.IPSECKEY]: IPSECKEYRecord,
  [types.RRSIG]: RRSIGRecord,
  [types.NSEC]: NSECRecord,
  [types.DNSKEY]: DNSKEYRecord,
  [types.DHCID]: DHCIDRecord,
  [types.NSEC3]: NSEC3Record,
  [types.NSEC3PARAM]: NSEC3PARAMRecord,
  [types.TLSA]: TLSARecord,
  [types.SMIMEA]: SMIMEARecord,
  [types.HIP]: HIPRecord,
  [types.NINFO]: NINFORecord,
  [types.RKEY]: RKEYRecord,
  [types.TALINK]: TALINKRecord,
  [types.CDS]: CDSRecord,
  [types.CDNSKEY]: CDNSKEYRecord,
  [types.OPENPGPKEY]: OPENPGPKEYRecord,
  [types.CSYNC]: CSYNCRecord,
  [types.SPF]: SPFRecord,
  [types.UINFO]: UINFORecord,
  [types.UID]: UIDRecord,
  [types.GID]: GIDRecord,
  [types.UNSPEC]: UNSPECRecord,
  [types.NID]: NIDRecord,
  [types.L32]: L32Record,
  [types.L64]: L64Record,
  [types.LP]: LPRecord,
  [types.EUI48]: EUI48Record,
  [types.EUI64]: EUI64Record,
  [types.URI]: URIRecord,
  [types.CAA]: CAARecord,
  [types.AVC]: AVCRecord,
  [types.TKEY]: TKEYRecord,
  [types.TSIG]: TSIGRecord,
  [types.IXFR]: null,
  [types.AXFR]: null,
  [types.MAILB]: null,
  [types.MAILA]: null,
  [types.ANY]: ANYRecord,
  [types.TA]: TARecord,
  [types.DLV]: DLVRecord,
  [types.NAMEPROOF]: NAMEPROOFRecord,
  [types.RESERVED]: null
};

/**
 * EDNS0 Option Classes
 * @const {Object}
 */

opts = {
  UNKNOWN: UNKNOWNOption,
  LLQ: LLQOption,
  UL: ULOption,
  NSID: NSIDOption,
  DAU: DAUOption,
  DHU: DHUOption,
  N3U: N3UOption,
  SUBNET: SUBNETOption,
  EXPIRE: EXPIREOption,
  COOKIE: COOKIEOption,
  TCPKEEPALIVE: TCPKEEPALIVEOption,
  PADDING: PADDINGOption,
  TRIEROOT: TRIEROOTOption,
  LOCAL: LOCALOption,
  LOCALSTART: LOCALOption,
  LOCALEND: LOCALOption
};

/**
 * EDNS0 Option Classes By Value
 * @const {Object}
 */

optsByVal = {
  [options.UNKNOWN]: UNKNOWNOption,
  [options.LLQ]: LLQOption,
  [options.UL]: ULOption,
  [options.NSID]: NSIDOption,
  [options.DAU]: DAUOption,
  [options.DHU]: DHUOption,
  [options.N3U]: N3UOption,
  [options.SUBNET]: SUBNETOption,
  [options.EXPIRE]: EXPIREOption,
  [options.COOKIE]: COOKIEOption,
  [options.TCPKEEPALIVE]: TCPKEEPALIVEOption,
  [options.PADDING]: PADDINGOption,
  [options.TRIEROOT]: TRIEROOTOption,
  [options.LOCAL]: LOCALOption,
  [options.LOCALSTART]: LOCALOption,
  [options.LOCALEND]: LOCALOption
};

/*
 * Decode
 */

function decode(type, data) {
  switch (type) {
    case types.UNKNOWN:
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
    case types.NAMEPROOF:
      return NAMEPROOFRecord.fromRaw(data);
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
    case types.UNKNOWN:
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
    case types.NAMEPROOF:
      rd = NAMEPROOFRecord.fromReader(cbr);
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
    case options.UNKNOWN:
      return UNKNOWNOption.fromRaw(data);
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
    case options.TRIEROOT:
      return TRIEROOTOption.fromRaw(data);
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
    case options.UNKNOWN:
      opt = UNKNOWNOption.fromReader(cbr);
      break;
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
    case options.TRIEROOT:
      opt = TRIEROOTOption.fromReader(cbr);
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

function fromZone(text) {
  const records = [];

  if (text.charCodeAt(0) === 0xfeff)
    text = text.substring(1);

  text = text.replace(/\r\n/g, '\n');
  text = text.replace(/\r/g, '\n');
  text = text.replace(/\\\n/g, '');

  for (const chunk of text.split('\n')) {
    const line = chunk.trim();

    if (line.length === 0)
      continue;

    if (line[0] === '#' || line[0] === ';')
      continue;

    records.push(Record.fromString(line));
  }

  return records;
}

function toZone(records) {
  assert(Array.isArray(records));

  const text = [];

  for (const rr of records) {
    assert(rr instanceof Record);
    text.push(rr.toString());
  }

  return text.join('\n');
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
exports.short = short;
exports.shortByVal = shortByVal;
exports.eflags = eflags;
exports.eflagsByVal = eflagsByVal;
exports.options = options;
exports.optionsByVal = optionsByVal;

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
exports.NAMEPROOFRecord = NAMEPROOFRecord;

exports.Option = Option;
exports.OptionData = OptionData;
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
exports.TRIEROOTOption = TRIEROOTOption;
exports.LOCALOption = LOCALOption;

exports.records = records;
exports.recordsByVal = recordsByVal;
exports.opts = opts;
exports.optsByVal = optsByVal;

exports.decode = decode;
exports.read = read;

exports.decodeOption = decodeOption;
exports.readOption = readOption;

exports.fromZone = fromZone;
exports.toZone = toZone;
