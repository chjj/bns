/*!
 * wire.js - wire types for bns
 * Copyright (c) 2018, Christopher Jeffrey (MIT License).
 * https://github.com/chjj/bns
 *
 * Parts of this software are based on miekg/dns and golang/go:
 *   https://github.com/miekg/dns/blob/master/msg.go
 *   https://github.com/miekg/dns/blob/master/types.go
 *   https://github.com/miekg/dns/blob/master/edns.go
 *   https://github.com/golang/go/blob/master/src/net/dnsmsg.go
 */

'use strict';

const assert = require('bsert');
const bio = require('bufio');
const IP = require('binet');
const constants = require('./constants');
const encoding = require('./encoding');
const lazy = require('./internal/lazy');
const util = require('./util');

const {
  Struct
} = bio;

const {
  sizeName,
  writeNameBW,
  readNameBR,
  sizeRawString,
  writeRawStringBW,
  readRawStringBR,
  sizeString,
  writeStringBW,
  readStringBR,
  readIP,
  writeIP,
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
  eflags,
  eflagsByVal,
  options,
  optionsByVal,
  keyFlags,
  algs,
  algsByVal,
  hashes,
  hashesByVal,
  algHashes,
  nsecHashes,
  nsecHashesByVal,
  certTypes,
  certTypesByVal,
  usages,
  usagesByVal,
  selectors,
  selectorsByVal,
  matchingTypes,
  matchingTypesByVal,
  sshAlgs,
  sshAlgsByVal,
  sshHashes,
  sshHashesByVal,
  tsigAlgs,
  tsigAlgsByVal,
  tkeyModes,
  tkeyModesByVal,
  YEAR68,
  LOC_EQUATOR,
  LOC_PRIMEMERIDIAN,
  LOC_HOURS,
  LOC_DEGREES,
  LOC_ALTITUDEBASE,
  MAX_NAME_SIZE,
  MAX_LABEL_SIZE,
  MAX_UDP_SIZE,
  STD_EDNS_SIZE,
  MAX_EDNS_SIZE,
  MAX_MSG_SIZE,
  DNS_PORT,
  DEFAULT_TTL,
  KSK_2010,
  KSK_2017,
  KSK_ARPA,
  opcodeToString,
  stringToOpcode,
  isOpcodeString,
  codeToString,
  stringToCode,
  isCodeString,
  typeToString,
  stringToType,
  isTypeString,
  classToString,
  stringToClass,
  isClassString,
  optionToString,
  stringToOption,
  isOptionString,
  algToString,
  stringToAlg,
  isAlgString,
  hashToString,
  stringToHash,
  isHashString
} = constants;

/*
 * Constants
 */

const DUMMY = Buffer.alloc(0);
const DUMMY4 = Buffer.alloc(4);
const DUMMY6 = Buffer.alloc(6);
const DUMMY8 = Buffer.alloc(8);
const POOL16 = Buffer.allocUnsafe(16);

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

class Message extends Struct {
  constructor() {
    super();

    this.id = 0;
    this.flags = 0;
    this.opcode = opcodes.QUERY;
    this.code = codes.NOERROR;
    this.question = [];
    this.answer = [];
    this.authority = [];
    this.additional = [];

    // Pseudo sections.
    this.edns = new EDNS();
    this.tsig = null;
    this.sig0 = null;

    // Extra properties.
    this.size = 0;
    this.malformed = false;
    this.trailing = DUMMY;
  }

  inject(msg) {
    assert(msg instanceof this.constructor);
    this.id = msg.id;
    this.flags = msg.flags;
    this.opcode = msg.opcode;
    this.code = msg.code;
    this.question = msg.question.slice();
    this.answer = msg.answer.slice();
    this.authority = msg.authority.slice();
    this.additional = msg.additional.slice();
    this.edns = msg.edns.clone();
    this.tsig = msg.tsig;
    this.sig0 = msg.sig0;
    this.size = msg.size;
    this.malformed = msg.malformed;
    this.trailing = msg.trailing;
    return this;
  }

  deepClone() {
    const msg = new this.constructor();
    return msg.decode(this.encode());
  }

  refresh() {
    this.size = 0;
    this.malformed = false;
    this.trailing = DUMMY;
    return this;
  }

  sections() {
    return [
      this.answer,
      this.authority,
      this.additional
    ];
  }

  *records() {
    for (const rr of this.answer)
      yield rr;

    for (const rr of this.authority)
      yield rr;

    for (const rr of this.additional)
      yield rr;
  }

  canonical() {
    for (const qs of this.question)
      qs.canonical();

    for (const rr of this.records())
      rr.canonical();

    this.edns.canonical();

    if (this.tsig)
      this.tsig.canonical();

    if (this.sig0)
      this.sig0.canonical();

    return this;
  }

  getFlag(bit) {
    return (this.flags & bit) !== 0;
  }

  setFlag(bit, value) {
    if (value)
      this.flags |= bit;
    else
      this.flags &= ~bit;

    return Boolean(value);
  }

  get qr() {
    return this.getFlag(flags.QR);
  }

  set qr(value) {
    return this.setFlag(flags.QR, value);
  }

  get aa() {
    return this.getFlag(flags.AA);
  }

  set aa(value) {
    return this.setFlag(flags.AA, value);
  }

  get tc() {
    return this.getFlag(flags.TC);
  }

  set tc(value) {
    return this.setFlag(flags.TC, value);
  }

  get rd() {
    return this.getFlag(flags.RD);
  }

  set rd(value) {
    return this.setFlag(flags.RD, value);
  }

  get ra() {
    return this.getFlag(flags.RA);
  }

  set ra(value) {
    return this.setFlag(flags.RA, value);
  }

  get z() {
    return this.getFlag(flags.Z);
  }

  set z(value) {
    return this.setFlag(flags.Z, value);
  }

  get ad() {
    return this.getFlag(flags.AD);
  }

  set ad(value) {
    return this.setFlag(flags.AD, value);
  }

  get cd() {
    return this.getFlag(flags.CD);
  }

  set cd(value) {
    return this.setFlag(flags.CD, value);
  }

  get qd() {
    return this.question;
  }

  set qd(value) {
    this.question = value;
  }

  get an() {
    return this.answer;
  }

  set an(value) {
    this.answer = value;
  }

  get ns() {
    return this.authority;
  }

  set ns(value) {
    this.authority = value;
  }

  get ar() {
    return this.additional;
  }

  set ar(value) {
    this.additional = value;
  }

  get qdcount() {
    return this.question.length;
  }

  get ancount() {
    return this.answer.length;
  }

  get nscount() {
    return this.authority.length;
  }

  get arcount() {
    let count = this.additional.length;

    if (this.edns.enabled)
      count += 1;

    if (this.tsig)
      count += 1;

    if (this.sig0)
      count += 1;

    return count;
  }

  setReply(req) {
    assert(req instanceof Message);

    this.id = req.id;
    this.opcode = req.opcode;
    this.qr = true;

    if (this.opcode === opcodes.QUERY) {
      this.rd = req.rd;
      this.cd = req.cd;
    }

    this.question = [];

    if (req.question.length > 0)
      this.question.push(req.question[0]);

    return this;
  }

  isEDNS() {
    return this.edns.enabled;
  }

  setEDNS(size, dnssec) {
    assert((size & 0xffff) === size);
    assert(typeof dnssec === 'boolean');

    this.edns.reset();
    this.edns.enabled = true;
    this.edns.size = size;
    this.edns.dnssec = dnssec;

    if (this.code > 0x0f)
      this.edns.code = this.code >>> 4;

    return this;
  }

  unsetEDNS() {
    this.edns.reset();

    if (this.code > 0x0f)
      this.code = codes.NOERROR;

    return this;
  }

  isDNSSEC() {
    if (!this.edns.enabled)
      return false;

    return this.edns.dnssec;
  }

  maxSize(max) {
    if (max == null)
      max = MAX_EDNS_SIZE;

    assert((max & 0xffff) === max);
    assert(max >= MAX_UDP_SIZE && max <= MAX_EDNS_SIZE);

    if (this.edns.enabled
        && this.edns.size >= MAX_UDP_SIZE) {
      return Math.min(max, this.edns.size);
    }

    return MAX_UDP_SIZE;
  }

  minTTL() {
    const now = util.now();

    let ttl = -1;

    for (const rr of this.records()) {
      if (rr.isOPT())
        continue;

      if (rr.ttl === 0)
        continue;

      if (ttl === -1 || rr.ttl < ttl)
        ttl = rr.ttl;

      if (rr.type === types.RRSIG) {
        const e = rr.data.expiration;
        const t = e - now;

        if (t > 0 && t < ttl)
          ttl = t;
      }
    }

    if (ttl === -1)
      ttl = 0;

    return ttl;
  }

  isAnswer() {
    if (this.answer.length > 0
        && (this.code === codes.NOERROR
        || this.code === codes.YXDOMAIN
        || this.code === codes.NXDOMAIN)) {
      return true;
    }

    return false;
  }

  isReferral() {
    if (this.isAnswer())
      return false;

    if (this.authority.length > 0
        && (this.code === codes.NOERROR
        || this.code === codes.YXDOMAIN)) {
      return true;
    }

    return false;
  }

  collect(name, type) {
    assert(typeof name === 'string');
    assert((type & 0xffff) === type);

    const result = [];

    let target = util.fqdn(name);

    for (const rr of this.answer) {
      if (!util.equal(rr.name, target))
        continue;

      if (rr.type === types.CNAME) {
        target = rr.data.target;

        if (type === types.ANY
            || type === types.CNAME) {
          result.push(rr);
        }

        continue;
      }

      if (type !== types.ANY) {
        if (rr.type !== type)
          continue;
      }

      result.push(rr);
    }

    return result;
  }

  getSize(map) {
    let size = 12;

    for (const qs of this.question)
      size += qs.getSize(map);

    for (const rr of this.answer)
      size += rr.getSize(map);

    for (const rr of this.authority)
      size += rr.getSize(map);

    for (const rr of this.additional)
      size += rr.getSize(map);

    if (this.edns.enabled)
      size += this.edns.getSize(map);

    if (this.tsig)
      size += this.tsig.getSize(map);

    if (this.sig0)
      size += this.sig0.getSize(map);

    return size;
  }

  write(bw, map) {
    bw.writeU16BE(this.id);

    let bits = this.flags;

    bits &= ~(0x0f << 11);
    bits |= (this.opcode & 0x0f) << 11;

    bits &= ~0x0f;
    bits |= this.code & 0x0f;

    bw.writeU16BE(bits);
    bw.writeU16BE(this.question.length);
    bw.writeU16BE(this.answer.length);
    bw.writeU16BE(this.authority.length);
    bw.writeU16BE(this.arcount);

    for (const qs of this.question)
      qs.write(bw, map);

    for (const rr of this.answer)
      rr.write(bw, map);

    for (const rr of this.authority)
      rr.write(bw, map);

    for (const rr of this.additional)
      rr.write(bw, map);

    if (this.code > 0x0f) {
      this.edns.enabled = true;
      this.edns.code = this.code >>> 4;
    }

    if (this.edns.enabled)
      this.edns.write(bw, map);

    if (this.tsig)
      this.tsig.write(bw, map);

    if (this.sig0)
      this.sig0.write(bw, map);

    return this;
  }

  encode(max) {
    const size = this.getSize();
    const bw = bio.write(size);

    this.write(bw, null);

    let msg = bw.render();

    if (max != null)
      msg = truncate(msg, max);

    if (msg.length > MAX_MSG_SIZE)
      throw new Error('Message exceeds size limits.');

    return msg;
  }

  compress(max) {
    const size = this.getSize();
    const bw = bio.write(size);
    const map = new Map();

    this.write(bw, map);

    let msg = bw.slice();

    if (max != null)
      msg = truncate(msg, max);

    if (msg.length > MAX_MSG_SIZE)
      throw new Error('Message exceeds size limits.');

    return msg;
  }

  read(br) {
    const size = br.data.length;
    const id = br.readU16BE();
    const bits = br.readU16BE();
    const qdcount = br.readU16BE();
    const ancount = br.readU16BE();
    const nscount = br.readU16BE();
    const arcount = br.readU16BE();

    this.size = size;
    this.id = id;
    this.flags = bits;
    this.flags &= ~(0x0f << 11);
    this.flags &= ~0x0f;
    this.opcode = (bits >>> 11) & 0x0f;
    this.code = bits & 0x0f;

    let tc = false;

    for (let i = 0; i < qdcount; i++) {
      if (br.left() === 0) {
        tc = true;
        break;
      }

      const qs = Question.read(br);

      this.question.push(qs);
    }

    for (let i = 0; i < ancount; i++) {
      if (br.left() === 0) {
        tc = true;
        break;
      }

      const rr = Record.read(br);

      this.answer.push(rr);
    }

    for (let i = 0; i < nscount; i++) {
      if (br.left() === 0) {
        tc = true;
        break;
      }

      const rr = Record.read(br);

      this.authority.push(rr);
    }

    for (let i = 0; i < arcount; i++) {
      if (br.left() === 0) {
        tc = true;
        break;
      }

      const rr = Record.read(br);

      if (rr.isOPT()) {
        this.edns.setRecord(rr);
        this.code &= 0x0f;
        this.code |= this.edns.code << 4;
        continue;
      }

      if (rr.isTSIG()) {
        this.tsig = rr;
        continue;
      }

      if (rr.isSIG0()) {
        this.sig0 = rr;
        continue;
      }

      this.additional.push(rr);
    }

    if (tc && !(bits & flags.TC))
      this.malformed = true;

    if (br.left() > 0)
      this.trailing = br.readBytes(br.left());

    return this;
  }

  toShort(name, type) {
    const qs = new Question(name, type);
    const rrs = this.collect(qs.name, qs.type);

    let out = '';

    for (const rr of rrs) {
      out += rr.data.toString();
      out += '\n';
    }

    return out;
  }

  toString(ms, host, port) {
    let diff = -1;
    let sec = -1;

    if (ms != null) {
      assert(Number.isSafeInteger(ms) && ms >= 0);
      diff = Math.max(0, Date.now() - ms);
      sec = Math.floor(ms / 1000);
    }

    if (host != null) {
      if (port == null)
        port = DNS_PORT;

      assert(typeof host === 'string');
      assert((port & 0xffff) === port);
    }

    const opcode = opcodeToString(this.opcode);
    const status = codeToString(this.code);
    const id = this.id.toString(10);
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
    str += `;; flags: ${flags.join(' ')};`;
    str += ` QUERY: ${this.question.length},`;
    str += ` ANSWER: ${this.answer.length},`;
    str += ` AUTHORITY: ${this.authority.length},`;
    str += ` ADDITIONAL: ${this.arcount}\n`;

    if (this.edns.enabled) {
      const version = this.edns.version;
      const flags = this.edns.dnssec ? ' do' : '';
      const udp = this.edns.size;

      str += '\n';
      str += ';; OPT PSEUDOSECTION:\n';
      str += `; EDNS: version: ${version}, flags:${flags}; udp: ${udp}`;

      for (const opt of this.edns.options) {
        str += '\n';
        str += '; ';
        str += opt.toString();
      }
    }

    if (this.question.length > 0) {
      str += '\n';
      str += ';; QUESTION SECTION:\n';

      for (const qs of this.question) {
        str += ';';
        str += qs.toString();
        str += '\n';
      }
    }

    if (this.answer.length > 0) {
      str += '\n';
      str += ';; ANSWER SECTION:\n';

      for (const rr of this.answer) {
        str += rr.toString();
        str += '\n';
      }
    }

    if (this.authority.length > 0) {
      str += '\n';
      str += ';; AUTHORITY SECTION:\n';

      for (const rr of this.authority) {
        str += rr.toString();
        str += '\n';
      }
    }

    if (this.additional.length > 0) {
      str += '\n';
      str += ';; ADDITIONAL SECTION:\n';

      for (const rr of this.additional) {
        str += rr.toString();
        str += '\n';
      }
    }

    if (this.tsig) {
      str += '\n';
      str += ';; TSIG PSEUDOSECTION:\n';
      str += this.tsig.toString();
      str += '\n';
    }

    if (this.sig0) {
      str += '\n';
      str += ';; SIG0 PSEUDOSECTION:\n';
      str += this.sig0.toString();
      str += '\n';
    }

    str += '\n';

    if (diff !== -1)
      str += `;; Query time: ${diff} msec\n`;

    if (host)
      str += `;; SERVER: ${host}#${port}(${host})\n`;

    if (sec !== -1)
      str += `;; WHEN: ${util.digDate(sec)}\n`;

    if (!this.size)
      this.size = this.getSize();

    if (this.size > 0)
      str += `;; MSG SIZE  rcvd: ${this.size}\n`;

    // Unbound style:
    if (this.trailing.length > 0) {
      str += '\n';
      str += ';; trailing garbage: 0x';
      str += this.trailing.toString('hex');
      str += '\n';
    }

    return str;
  }

  fromString(str) {
    let opcode = 0;
    let code = 0;
    let id = 0;
    let qdcount = 0;
    let ancount = 0;
    let nscount = 0;
    let arcount = 0;
    let enabled = false;
    let version = 0;
    let dnssec = false;
    let udp = MAX_UDP_SIZE;
    let options = null;
    let question = null;
    let answer = null;
    let authority = null;
    let additional = null;
    let tsig = null;
    let sig0 = null;
    let size = 0;
    let trailing = DUMMY;
    let index = -1;

    const lines = util.splitLines(str);

    const read = () => {
      index += 1;
      if (index === lines.length)
        throw new Error('Unexpected EOF.');
      return lines[index];
    };

    const expect = (prefix) => {
      const line = read();
      if (!util.startsWith(line, prefix))
        throw new Error('Unexpected line.');
      return line;
    };

    const seek = (prefix) => {
      for (;;) {
        const line = read();
        if (util.startsWith(line, prefix))
          return line;
      }
    };

    const find = (prefix) => {
      const i = index;
      try {
        return seek(prefix);
      } catch (e) {
        index = i;
        return null;
      }
    };

    const peek = () => {
      if (index + 1 === lines.length)
        return '';
      const line = read();
      index -= 1;
      return line;
    };

    const hdrLine = seek(';; ->>HEADER<<-');
    const hdr = util.splitSP(hdrLine, 9);

    assert(hdr.length === 8);
    assert(hdr[0] === ';;');
    assert(hdr[1] === '->>HEADER<<-');
    assert(hdr[2] === 'opcode:');
    assert(util.endsWith(hdr[3], ','));
    assert(hdr[4] === 'status:');
    assert(util.endsWith(hdr[5], ','));
    assert(hdr[6] === 'id:');
    assert(!util.endsWith(hdr[7], ','));

    opcode = stringToOpcode(hdr[3].slice(0, -1));
    code = stringToCode(hdr[5].slice(0, -1));
    id = util.parseU16(hdr[7]);

    const subLine = expect(';; flags:');
    const sub = util.splitSP(subLine);

    assert(sub.length >= 9);
    assert(sub[0] === ';;');

    if (sub[1] === 'flags:;') {
      sub[1] = 'flags:';
      sub.splice(2, 0, ';');
    }

    assert(sub[1] === 'flags:');

    let bits = 0;
    let counts = null;

    for (let i = 2; i < sub.length; i++) {
      let flag = sub[i];

      const end = flag[flag.length - 1] === ';';

      if (end)
        flag = flag.slice(0, -1);

      switch (flag) {
        case '':
          break;
        case 'qr':
          bits |= flags.QR;
          break;
        case 'aa':
          bits |= flags.AA;
          break;
        case 'tc':
          bits |= flags.TC;
          break;
        case 'rd':
          bits |= flags.RD;
          break;
        case 'ra':
          bits |= flags.RA;
          break;
        case 'z':
          bits |= flags.Z;
          break;
        case 'ad':
          bits |= flags.AD;
          break;
        case 'cd':
          bits |= flags.CD;
          break;
        default:
          throw new Error(`Unknown flag: ${flag}.`);
      }

      if (end) {
        counts = sub.slice(i + 1);
        break;
      }
    }

    if (!counts)
      throw new Error('Malformed subheader.');

    assert(counts.length === 8);
    assert(counts[0] === 'QUERY:');
    assert(util.endsWith(counts[1], ','));
    assert(counts[2] === 'ANSWER:');
    assert(util.endsWith(counts[3], ','));
    assert(counts[4] === 'AUTHORITY:');
    assert(util.endsWith(counts[5], ','));
    assert(counts[6] === 'ADDITIONAL:');
    assert(!util.endsWith(counts[7], ','));

    qdcount = util.parseU16(counts[1].slice(0, -1));
    ancount = util.parseU16(counts[3].slice(0, -1));
    nscount = util.parseU16(counts[5].slice(0, -1));
    arcount = util.parseU16(counts[7]);
    options = [];

    if (find(';; OPT PSEUDOSECTION:')) {
      const line = expect('; EDNS: version: ');

      const hdr = util.splitSP(line);
      assert(hdr.length >= 7);
      assert(util.endsWith(hdr[3], ','));

      if (hdr[4] === 'flags:;') {
        hdr[4] = 'flags:';
        hdr.splice(5, 0, ';');
      }

      assert(hdr[4] === 'flags:');

      enabled = true;
      version = util.parseU8(hdr[3].slice(0, -1));

      assert(arcount > 0);
      arcount -= 1;

      let sub = null;

      for (let i = 5; i < hdr.length; i++) {
        let flag = hdr[i];

        const end = flag[flag.length - 1] === ';';

        if (end)
          flag = flag.slice(0, -1);

        switch (flag) {
          case '':
            break;
          case 'do':
            dnssec = true;
            break;
          default:
            throw new Error(`Unknown EDNS flag: ${flag}.`);
        }

        if (end) {
          sub = hdr.slice(i + 1);
          break;
        }
      }

      if (!sub)
        throw new Error('Malformed EDNS header.');

      assert(sub.length === 2);
      assert(sub[0] === 'udp:');

      udp = util.parseU16(sub[1]);

      while (util.startsWith(peek(), '; ')) {
        let line = read().substring(2);

        // Hack.
        if (util.startsWith(line, 'COOKIE: ')
            && util.endsWith(line, ' (echoed)')) {
          line = line.slice(0, -9);
        }

        options.push(Option.fromString(line));
      }
    }

    question = [];

    if (qdcount > 0) {
      seek(';; QUESTION SECTION:');

      for (let i = 0; i < qdcount; i++) {
        const line = read();

        assert(line[0] === ';');

        const text = line.substring(1);
        const qs = Question.fromString(text);

        question.push(qs);
      }
    }

    answer = [];

    if (ancount > 0) {
      seek(';; ANSWER SECTION:');

      for (let i = 0; i < ancount; i++) {
        const line = read();
        const rr = Record.fromString(line);

        answer.push(rr);
      }
    }

    authority = [];

    if (nscount > 0) {
      seek(';; AUTHORITY SECTION:');

      for (let i = 0; i < nscount; i++) {
        const line = read();
        const rr = Record.fromString(line);

        authority.push(rr);
      }
    }

    additional = [];

    if (arcount > 0) {
      const section = seek(';; ');

      switch (section) {
        case ';; ADDITIONAL SECTION:':
        case ';; TSIG PSEUDOSECTION:':
        case ';; SIG0 PSEUDOSECTION:':
          break;
        default:
          throw new Error('Unexpected section.');
      }

      for (let i = 0; i < arcount; i++) {
        const line = read();

        if (line[0] === ';') {
          arcount += 1;
          continue;
        }

        const rr = Record.fromString(line);

        if (rr.isTSIG()) {
          tsig = rr;
          continue;
        }

        if (rr.isSIG0()) {
          sig0 = rr;
          continue;
        }

        additional.push(rr);
      }
    }

    const sizeLine = find(';; MSG SIZE  rcvd: ');

    if (sizeLine) {
      const text = sizeLine.substring(19);
      size = util.parseU32(text);
    }

    const garbageLine = find(';; trailing garbage: 0x');

    if (garbageLine) {
      const text = garbageLine.substring(23);
      trailing = util.parseHex(text);
    }

    this.opcode = opcode;
    this.code = code;
    this.id = id;
    this.flags = bits;

    this.edns.enabled = enabled;
    this.edns.version = version;
    this.edns.dnssec = dnssec;
    this.edns.size = udp;
    this.edns.code = code >>> 4;
    this.edns.options = options;

    this.question = question;
    this.answer = answer;
    this.authority = authority;
    this.additional = additional;
    this.tsig = tsig;
    this.sig0 = sig0;

    this.size = size;
    this.malformed = false;
    this.trailing = trailing;

    return this;
  }

  getJSON() {
    if (!this.size)
      this.size = this.getSize();

    return {
      id: this.id,
      opcode: opcodeToString(this.opcode),
      code: codeToString(this.code),
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
      additional: this.additional.map(rr => rr.toJSON()),
      edns: this.edns.enabled ? this.edns.toJSON() : undefined,
      tsig: this.tsig ? this.tsig.data.toJSON() : undefined,
      sig0: this.sig0 ? this.sig0.data.toJSON() : undefined,
      size: this.size,
      trailing: this.trailing.length > 0
        ? this.trailing.toString('hex')
        : undefined
    };
  }

  fromJSON(json) {
    assert(json && typeof json === 'object');
    assert((json.id & 0xffff) === json.id);
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
    this.opcode = stringToOpcode(json.opcode);
    this.code = stringToCode(json.code);
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

    for (const rr of json.additional) {
      const record = Record.fromJSON(rr);

      assert(!record.isOPT());
      assert(!record.isTSIG());
      assert(!record.isSIG0());

      this.additional.push(record);
    }

    if (json.edns != null) {
      this.edns.fromJSON(json.edns);
      this.code &= 0x0f;
      this.code |= this.edns.code << 4;
    }

    if (json.tsig != null) {
      this.tsig = new Record();
      this.tsig.name = '.';
      this.tsig.type = types.TSIG;
      this.tsig.class = classes.ANY;
      this.tsig.ttl = 0;
      this.tsig.data = TSIGRecord.fromJSON(json.tsig);
    }

    if (json.sig0 != null) {
      this.sig0 = new Record();
      this.sig0.name = '.';
      this.sig0.type = types.SIG;
      this.sig0.class = classes.ANY;
      this.sig0.ttl = 0;
      this.sig0.data = SIGRecord.fromJSON(json.sig0);
    }

    if (json.size != null) {
      assert((json.size >>> 0) === json.size);
      this.size = json.size;
    }

    this.malformed = false;

    if (json.trailing != null)
      this.trailing = util.parseHex(json.trailing);

    return this;
  }
}

/**
 * EDNS
 */

class EDNS extends Struct {
  constructor() {
    super();

    this.enabled = false;
    this.size = MAX_UDP_SIZE;
    this.code = 0;
    this.version = 0;
    this.flags = 0;
    this.options = [];
  }

  inject(edns) {
    assert(edns instanceof this.constructor);
    this.enabled = edns.enabled;
    this.size = edns.size;
    this.code = edns.code;
    this.version = edns.version;
    this.flags = edns.flags;
    this.options = edns.options.slice();
    return this;
  }

  clone() {
    const copy = new this.constructor();
    return copy.inject(this);
  }

  reset() {
    this.enabled = false;
    this.size = MAX_UDP_SIZE;
    this.code = 0;
    this.version = 0;
    this.flags = 0;
    this.options = [];
    return this;
  }

  canonical() {
    // Note: not mentioned in RFC 4034.
    for (const opt of this.options)
      opt.canonical();
    return this;
  }

  getFlag(bit) {
    return (this.flags & bit) !== 0;
  }

  setFlag(bit, value) {
    if (value)
      this.flags |= bit;
    else
      this.flags &= ~bit;

    return Boolean(value);
  }

  get dnssec() {
    return this.getFlag(eflags.DO);
  }

  set dnssec(value) {
    return this.setFlag(eflags.DO, value);
  }

  set(code, option) {
    assert((code & 0xffff) === code);
    assert(option instanceof OptionData);

    const opt = new Option();
    opt.code = code;
    opt.option = option;

    for (let i = 0; i < this.options.length; i++) {
      const item = this.options[i];
      if (item.code === code) {
        this.options[i] = opt;
        return this;
      }
    }

    this.options.push(opt);

    return this;
  }

  get(code) {
    assert((code & 0xffff) === code);

    for (const opt of this.options) {
      if (opt.code === code)
        return opt.option;
    }

    return null;
  }

  has(code) {
    return this.get(code) != null;
  }

  remove(code) {
    assert((code & 0xffff) === code);

    for (let i = 0; i < this.options.length; i++) {
      const opt = this.options[i];
      if (opt.code === code) {
        this.options.splice(i, 1);
        return opt.option;
      }
    }

    return null;
  }

  add(option) {
    assert(option instanceof OptionData);
    assert(option.code !== options.RESERVED);
    return this.set(option.code, option);
  }

  setCookie(cookie) {
    assert(Buffer.isBuffer(cookie));
    const option = new COOKIEOption();
    option.cookie = cookie;
    return this.add(option);
  }

  getCookie() {
    const opt = this.get(options.COOKIE);

    if (!opt)
      return null;

    return opt.cookie;
  }

  hasCookie() {
    return this.getCookie() != null;
  }

  removeCookie() {
    const opt = this.remove(options.COOKIE);

    if (!opt)
      return null;

    return opt.cookie;
  }

  getDataSize(map) {
    let size = 0;
    for (const opt of this.options)
      size += opt.getSize(map);
    return size;
  }

  getSize(map) {
    let size = 0;
    size += 1;
    size += 10;
    size += this.getDataSize(map);
    return size;
  }

  write(bw, map) {
    bw.writeU8(0);
    bw.writeU16BE(types.OPT);
    bw.writeU16BE(this.size);

    bw.writeU8(this.code);
    bw.writeU8(this.version);
    bw.writeU16BE(this.flags);

    bw.writeU16BE(0);

    const off = bw.offset;

    for (const opt of this.options)
      opt.write(bw, map);

    const size = bw.offset - off;

    bio.writeU16BE(bw.data, size, off - 2);

    return this;
  }

  read(br) {
    assert(br.readU8() === 0);
    assert(br.readU16BE() === types.OPT);

    this.size = br.readU16BE();

    this.code = br.readU8();
    this.version = br.readU8();
    this.flags = br.readU16BE();

    const size = br.readU16BE();
    const child = br.readChild(size);

    while (child.left())
      this.options.push(Option.read(child));

    return this;
  }

  setRecord(rr) {
    assert(rr instanceof Record);
    assert(rr.type === types.OPT);

    const rd = rr.data;

    this.enabled = true;
    this.size = rr.class;
    this.code = (rr.ttl >>> 24) & 0xff;
    this.version = (rr.ttl >>> 16) & 0xff;
    this.flags = rr.ttl & 0xffff;
    this.options = [];

    for (const opt of rd.options)
      this.options.push(opt);

    return this;
  }

  toRecord() {
    const rr = new Record();
    const rd = new OPTRecord();

    rr.name = '.';
    rr.type = types.OPT;

    rr.class = this.size;

    rr.ttl |= (this.code & 0xff) << 24;
    rr.ttl |= (this.version & 0xff) << 16;
    rr.ttl |= this.flags & 0xffff;
    rr.ttl >>>= 0;

    rr.data = rd;

    for (const opt of this.options)
      rd.options.push(opt);

    return rr;
  }

  fromRecord(rr) {
    return this.setRecord(rr);
  }

  static fromRecord(rr) {
    return new this().fromRecord(rr);
  }

  getJSON() {
    return {
      enabled: this.enabled,
      size: this.size,
      code: this.code,
      version: this.version,
      dnssec: this.dnssec,
      options: this.options.map(opt => opt.toJSON())
    };
  }

  fromJSON(json) {
    assert(json && typeof json === 'object');
    assert(typeof json.enabled === 'boolean');
    assert((json.size & 0xffff) === json.size);
    assert((json.code & 0xff) === json.code);
    assert((json.version & 0xff) === json.version);
    assert(typeof json.dnssec === 'boolean');
    assert(Array.isArray(json.options));

    this.enabled = json.enabled;
    this.size = json.size;
    this.code = json.code;
    this.version = json.version;
    this.dnssec = json.dnssec;

    for (const opt of json.options)
      this.options.push(Option.fromJSON(opt));

    return this;
  }
}

/**
 * Question
 */

class Question extends Struct {
  constructor(name, type) {
    super();

    if (name == null)
      name = '';

    if (type == null)
      type = types.ANY;

    if (typeof type === 'string')
      type = stringToType(type);

    assert(typeof name === 'string');
    assert((type & 0xffff) === type);

    this.name = util.fqdn(name);
    this.type = type;
    this.class = classes.IN;
  }

  equals(qs) {
    assert(qs instanceof Question);
    return util.equal(this.name, qs.name)
      && this.type === qs.type
      && this.class === qs.class;
  }

  inject(qs) {
    assert(qs instanceof this.constructor);
    this.name = qs.name;
    this.type = qs.type;
    this.class = qs.class;
    return this;
  }

  clone() {
    const qs = new this.constructor();
    return qs.inject(this);
  }

  canonical() {
    // Note: not mentioned in RFC 4034.
    this.name = this.name.toLowerCase();
    return this;
  }

  getSize(map) {
    return sizeName(this.name, map) + 4;
  }

  write(bw, map) {
    writeNameBW(bw, this.name, map);
    bw.writeU16BE(this.type);
    bw.writeU16BE(this.class);
    return this;
  }

  read(br) {
    this.name = readNameBR(br);

    if (br.left() === 0)
      return this;

    this.type = br.readU16BE();

    if (br.left() === 0)
      return this;

    this.class = br.readU16BE();

    return this;
  }

  toString() {
    const name = this.name;
    const class_ = classToString(this.class);
    const type = typeToString(this.type);
    return `${name} ${class_} ${type}`;
  }

  fromString(str) {
    const parts = util.splitSP(str, 4);

    assert(parts.length === 3);
    assert(encoding.isName(parts[0]));

    this.name = parts[0];
    this.class = stringToClass(parts[1]);
    this.type = stringToType(parts[2]);

    return this;
  }

  getJSON() {
    return {
      name: this.name,
      class: classToString(this.class),
      type: typeToString(this.type)
    };
  }

  fromJSON(json) {
    assert(json && typeof json === 'object');
    assert(typeof json.name === 'string');
    assert(encoding.isName(json.name));

    this.name = json.name;
    this.class = stringToClass(json.class);
    this.type = stringToType(json.type);

    return this;
  }
}

/**
 * Record
 */

class Record extends Struct {
  constructor() {
    super();
    this.name = '.';
    this.type = types.UNKNOWN;
    this.class = classes.IN;
    this.ttl = 0;
    this.data = new UNKNOWNRecord();
  }

  inject(rr) {
    assert(rr instanceof this.constructor);
    this.name = rr.name;
    this.type = rr.type;
    this.class = rr.class;
    this.ttl = rr.ttl;
    this.data = rr.data;
    return this;
  }

  deepClone() {
    const rr = new this.constructor();
    return rr.decode(this.encode());
  }

  canonical() {
    this.name = this.name.toLowerCase();
    this.data.canonical();
    return this;
  }

  isOPT() {
    return this.type === types.OPT;
  }

  isTSIG() {
    return this.name === '.'
        && this.type === types.TSIG
        && this.class === classes.ANY
        && this.ttl === 0;
  }

  isSIG0() {
    return this.name === '.'
        && this.type === types.SIG
        && this.class === classes.ANY
        && this.ttl === 0
        && this.data.typeCovered === 0;
  }

  getSize(map) {
    let size = 0;
    size += sizeName(this.name, map);
    size += 10;
    size += this.data.getSize(map);
    return size;
  }

  write(bw, map) {
    writeNameBW(bw, this.name, map);
    bw.writeU16BE(this.type);
    bw.writeU16BE(this.class);
    bw.writeU32BE(this.ttl);
    bw.writeU16BE(0);

    const off = bw.offset;

    this.data.write(bw, map);

    const size = bw.offset - off;

    bio.writeU16BE(bw.data, size, off - 2);

    return this;
  }

  read(br) {
    this.name = readNameBR(br);
    this.type = br.readU16BE();
    this.class = br.readU16BE();
    this.ttl = br.readU32BE();

    const size = br.readU16BE();
    const child = br.readChild(size);

    this.data = readData(this.type, child);

    return this;
  }

  toString() {
    const name = this.name;
    const ttl = this.ttl.toString(10);
    const class_ = classToString(this.class);
    const type = typeToString(this.type);
    const isUnknown = typesByVal[this.type] == null;

    let body = this.data.toString();

    if (isUnknown) {
      assert(this.data.type === types.UNKNOWN);
      const size = this.data.getSize().toString(10);
      body = `\\# ${size} ${body}`;
    }

    return `${name} ${ttl} ${class_} ${type} ${body}`;
  }

  fromString(str) {
    const scan = lazy('./internal/scan');
    const rr = scan.parseRecord(exports, str);
    return this.inject(rr);
  }

  getJSON() {
    return {
      name: this.name,
      ttl: this.ttl,
      class: classToString(this.class),
      type: typeToString(this.type),
      data: this.data.toJSON()
    };
  }

  fromJSON(json) {
    assert(json && typeof json === 'object');
    assert(typeof json.name === 'string');
    assert(encoding.isName(json.name));
    assert((json.ttl >>> 0) === json.ttl);
    assert(json.data && typeof json.data === 'object');

    this.name = json.name;
    this.ttl = json.ttl;
    this.class = stringToClass(json.class);
    this.type = stringToType(json.type);

    const RD = recordsByVal[this.type];

    let data;
    if (types[json.type] == null) {
      const rd = util.parseHex(json.data.data);

      if (RD)
        data = RD.decode(rd);
      else
        data = UNKNOWNRecord.decode(rd);
    } else {
      if (!RD)
        throw new Error(`Unknown record type: ${json.type}.`);

      data = RD.fromJSON(json.data);
    }

    this.data = data;

    return this;
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

  _schema() {
    const schema = lazy('./internal/schema');
    const s = schema.records[this.type];

    if (!s)
      return schema.records[types.UNKNOWN];

    return s;
  }

  canonical() {
    return this;
  }

  toString() {
    const schema = lazy('./internal/schema');
    return schema.toString(exports, this, this._schema());
  }

  fromString(str) {
    const scan = lazy('./internal/scan');
    const rd = scan.parseData(exports, this.type, str);
    return this.inject(rd);
  }

  getJSON() {
    const schema = lazy('./internal/schema');
    return schema.toJSON(exports, this, this._schema());
  }

  fromJSON(json) {
    const schema = lazy('./internal/schema');
    return schema.fromJSON(exports, this, this._schema(), json);
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

  write(bw) {
    bw.writeBytes(this.data);
    return this;
  }

  read(br) {
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

  write(bw) {
    writeIP(bw, this.address, 4);
    return this;
  }

  read(br) {
    this.address = readIP(br, 4);
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

  canonical() {
    this.ns = this.ns.toLowerCase();
    return this;
  }

  getSize(map) {
    return sizeName(this.ns, map);
  }

  write(bw, map) {
    writeNameBW(bw, this.ns, map);
    return this;
  }

  read(br) {
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

  canonical() {
    this.md = this.md.toLowerCase();
    return this;
  }

  getSize(map) {
    return sizeName(this.md, map);
  }

  write(bw, map) {
    writeNameBW(bw, this.md, map);
    return this;
  }

  read(br) {
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

  canonical() {
    this.mf = this.mf.toLowerCase();
    return this;
  }

  getSize(map) {
    return sizeName(this.mf, map);
  }

  write(bw, map) {
    writeNameBW(bw, this.mf, map);
    return this;
  }

  read(br) {
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

  canonical() {
    this.target = this.target.toLowerCase();
    return this;
  }

  getSize(map) {
    return sizeName(this.target, map);
  }

  write(bw, map) {
    writeNameBW(bw, this.target, map);
    return this;
  }

  read(br) {
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

  canonical() {
    this.ns = this.ns.toLowerCase();
    this.mbox = this.mbox.toLowerCase();
    return this;
  }

  getSize(map) {
    let size = 0;
    size += sizeName(this.ns, map);
    size += sizeName(this.mbox, map);
    size += 20;
    return size;
  }

  write(bw, map) {
    writeNameBW(bw, this.ns, map);
    writeNameBW(bw, this.mbox, map);
    bw.writeU32BE(this.serial);
    bw.writeU32BE(this.refresh);
    bw.writeU32BE(this.retry);
    bw.writeU32BE(this.expire);
    bw.writeU32BE(this.minttl);
    return this;
  }

  read(br) {
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

  canonical() {
    this.mb = this.mb.toLowerCase();
    return this;
  }

  getSize(map) {
    return sizeName(this.mb, map);
  }

  write(bw, map) {
    writeNameBW(bw, this.mb, map);
    return this;
  }

  read(br) {
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

  canonical() {
    this.mg = this.mg.toLowerCase();
    return this;
  }

  getSize(map) {
    return sizeName(this.mg, map);
  }

  write(bw, map) {
    writeNameBW(bw, this.mg, map);
    return this;
  }

  read(br) {
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

  canonical() {
    this.mr = this.mr.toLowerCase();
    return this;
  }

  getSize(map) {
    return sizeName(this.mr, map);
  }

  write(bw, map) {
    writeNameBW(bw, this.mr, map);
    return this;
  }

  read(br) {
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

  setPorts(ports) {
    this.bitmap = encoding.toPortmap(ports);
    return this;
  }

  getPorts() {
    return encoding.fromPortmap(this.bitmap);
  }

  hasPort(port) {
    return encoding.hasPort(this.bitmap, port);
  }

  getSize() {
    return 5 + this.bitmap.length;
  }

  write(bw) {
    writeIP(bw, this.address, 4);
    bw.writeU8(this.protocol);
    bw.writeBytes(this.bitmap);
    return this;
  }

  read(br) {
    this.address = readIP(br, 4);
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

  canonical() {
    this.ptr = this.ptr.toLowerCase();
    return this;
  }

  getSize(map) {
    return sizeName(this.ptr, map);
  }

  write(bw, map) {
    writeNameBW(bw, this.ptr, map);
    return this;
  }

  read(br) {
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
    let size = 0;
    size += sizeString(this.cpu);
    size += sizeString(this.os);
    return size;
  }

  write(bw) {
    writeStringBW(bw, this.cpu);
    writeStringBW(bw, this.os);
    return this;
  }

  read(br) {
    this.cpu = readStringBR(br);
    this.os = readStringBR(br);
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

  canonical() {
    this.rmail = this.rmail.toLowerCase();
    this.email = this.email.toLowerCase();
    return this;
  }

  getSize(map) {
    let size = 0;
    size += sizeName(this.rmail, map);
    size += sizeName(this.email, map);
    return size;
  }

  write(bw, map) {
    writeNameBW(bw, this.rmail, map);
    writeNameBW(bw, this.email, map);
    return this;
  }

  read(br) {
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

  canonical() {
    this.mx = this.mx.toLowerCase();
    return this;
  }

  getSize(map) {
    return 2 + sizeName(this.mx, map);
  }

  write(bw, map) {
    bw.writeU16BE(this.preference);
    writeNameBW(bw, this.mx, map);
    return this;
  }

  read(br) {
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
      size += sizeString(txt);
    return size;
  }

  write(bw) {
    for (const txt of this.txt)
      writeStringBW(bw, txt);
    return this;
  }

  read(br) {
    while (br.left())
      this.txt.push(readStringBR(br));
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
    this.mbox = '.';
    this.txt = '.';
  }

  get type() {
    return types.RP;
  }

  canonical() {
    this.mbox = this.mbox.toLowerCase();
    this.txt = this.txt.toLowerCase();
    return this;
  }

  getSize(map) {
    let size = 0;
    size += sizeName(this.mbox, map);
    size += sizeName(this.txt, map);
    return size;
  }

  write(bw, map) {
    writeNameBW(bw, this.mbox, map);
    writeNameBW(bw, this.txt, map);
    return this;
  }

  read(br) {
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

  canonical() {
    this.hostname = this.hostname.toLowerCase();
    return this;
  }

  getSize(map) {
    return 2 + sizeName(this.hostname, map);
  }

  write(bw, map) {
    bw.writeU16BE(this.subtype);
    writeNameBW(bw, this.hostname, map);
    return this;
  }

  read(br) {
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
    return sizeString(this.psdnAddress);
  }

  write(bw) {
    writeStringBW(bw, this.psdnAddress);
    return this;
  }

  read(br) {
    this.psdnAddress = readStringBR(br, true);
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
    let size = 0;
    size += sizeString(this.address);
    size += sizeString(this.sa);
    return size;
  }

  write(bw) {
    writeStringBW(bw, this.address);
    writeStringBW(bw, this.sa);
    return this;
  }

  read(br) {
    this.address = readStringBR(br, true);
    this.sa = readStringBR(br, true);
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

  canonical() {
    this.host = this.host.toLowerCase();
    return this;
  }

  getSize(map) {
    return 2 + sizeName(this.host, map);
  }

  write(bw, map) {
    bw.writeU16BE(this.preference);
    writeNameBW(bw, this.host, map);
    return this;
  }

  read(br) {
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

  write(bw) {
    bw.writeBytes(this.nsap);
    return this;
  }

  read(br) {
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

  canonical() {
    this.signerName = this.signerName.toLowerCase();
    return this;
  }

  getSize(map) {
    let size = 0;
    size += 18;
    size += sizeName(this.signerName, map);
    size += this.signature.length;
    return size;
  }

  write(bw, map) {
    bw.writeU16BE(this.typeCovered);
    bw.writeU8(this.algorithm);
    bw.writeU8(this.labels);
    bw.writeU32BE(this.origTTL);
    bw.writeU32BE(this.expiration);
    bw.writeU32BE(this.inception);
    bw.writeU16BE(this.keyTag);
    writeNameBW(bw, this.signerName, map);
    bw.writeBytes(this.signature);
    return this;
  }

  read(br) {
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
      raw = this.encode();
    } finally {
      this.signerName = signerName;
      this.signature = signature;
    }

    return raw;
  }

  validityPeriod(t) {
    if (t == null)
      t = util.now();

    assert(Number.isSafeInteger(t) && t >= 0);

    return t >= this.inception && t <= this.expiration;
  }

  getJSON() {
    const json = super.getJSON();
    json.algName = algToString(this.algorithm);
    return json;
  }

  toString() {
    const algName = algToString(this.algorithm);

    let str = super.toString();

    // Mimic `delv`.
    str += ' ';
    str += ` ; alg = ${algName}`;

    return str;
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

  write(bw) {
    bw.writeU16BE(this.flags);
    bw.writeU8(this.protocol);
    bw.writeU8(this.algorithm);
    bw.writeBytes(this.publicKey);
    return this;
  }

  read(br) {
    this.flags = br.readU16BE();
    this.protocol = br.readU8();
    this.algorithm = br.readU8();
    this.publicKey = br.readBytes(br.left());
    return this;
  }

  keyTag(raw) {
    if (this.algorithm === algs.RSAMD5) {
      const key = this.publicKey;

      if (key.length < 2)
        return 0;

      return bio.readU16BE(key, key.length - 2);
    }

    if (!raw)
      raw = this.encode();

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

  revTag(raw) {
    if (!(this.flags & keyFlags.REVOKE))
      return this.keyTag(raw);

    this.flags &= ~keyFlags.REVOKE;

    try {
      return this.keyTag(raw);
    } finally {
      this.flags |= keyFlags.REVOKE;
    }
  }

  getJSON() {
    let type = 'ZSK';

    if (this.flags & keyFlags.SEP)
      type = 'KSK';

    const json = super.getJSON();

    json.keyType = type;
    json.keyTag = this.keyTag();
    json.algName = algToString(this.algorithm);

    if (isRSA(this.algorithm))
      json.bits = rsaBits(this.publicKey);

    return json;
  }

  toString() {
    let type = 'ZSK';

    if (this.flags & keyFlags.SEP)
      type = 'KSK';

    const algName = algToString(this.algorithm);
    const keyTag = this.keyTag();

    let str = super.toString();

    // Mimic `delv`.
    str += ' ';
    str += ` ; ${type}`;
    str += ` ; alg = ${algName}`;

    if (isRSA(this.algorithm)) {
      const [n, e] = rsaBits(this.publicKey);
      str += ` ; bits = ${n},${e}`;
    }

    str += ` ; key id = ${keyTag}`;

    return str;
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
    this.map822 = '.';
    this.mapx400 = '.';
  }

  get type() {
    return types.PX;
  }

  canonical() {
    this.map822 = this.map822.toLowerCase();
    this.mapx400 = this.mapx400.toLowerCase();
    return this;
  }

  getSize(map) {
    let size = 0;
    size += 2;
    size += sizeName(this.map822, map);
    size += sizeName(this.mapx400, map);
    return size;
  }

  write(bw, map) {
    bw.writeU16BE(this.preference);
    writeNameBW(bw, this.map822, map);
    writeNameBW(bw, this.mapx400, map);
    return this;
  }

  read(br) {
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
    let size = 0;
    size += sizeString(this.longitude);
    size += sizeString(this.latitude);
    size += sizeString(this.altitude);
    return size;
  }

  write(bw) {
    writeStringBW(bw, this.longitude);
    writeStringBW(bw, this.latitude);
    writeStringBW(bw, this.altitude);
    return this;
  }

  read(br) {
    this.longitude = readStringBR(br, true);
    this.latitude = readStringBR(br, true);
    this.altitude = readStringBR(br, true);
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

  write(bw) {
    writeIP(bw, this.address, 16);
    return this;
  }

  read(br) {
    this.address = readIP(br, 16);
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

  write(bw) {
    bw.writeU8(this.version);
    bw.writeU8(this.size);
    bw.writeU8(this.horizPre);
    bw.writeU8(this.vertPre);
    bw.writeU32BE(this.latitude);
    bw.writeU32BE(this.longitude);
    bw.writeU32BE(this.altitude);
    return this;
  }

  read(br) {
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
 * @see https://tools.ietf.org/html/rfc2535#section-5.1
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

  canonical() {
    this.nextDomain = this.nextDomain.toLowerCase();
    return this;
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

  getSize(map) {
    let size = 0;
    size += sizeName(this.nextDomain, map);
    size += this.typeBitmap.length;
    return size;
  }

  write(bw, map) {
    writeNameBW(bw, this.nextDomain, map);
    bw.writeBytes(this.typeBitmap);
    return this;
  }

  read(br) {
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

  write(bw) {
    bw.writeBytes(this.endpoint);
    return this;
  }

  read(br) {
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

  write(bw) {
    bw.writeBytes(this.locator);
    return this;
  }

  read(br) {
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

  canonical() {
    this.target = this.target.toLowerCase();
    return this;
  }

  getSize(map) {
    return 6 + sizeName(this.target, map);
  }

  write(bw, map) {
    bw.writeU16BE(this.priority);
    bw.writeU16BE(this.weight);
    bw.writeU16BE(this.port);
    writeNameBW(bw, this.target, map);
    return this;
  }

  read(br) {
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

  write(bw) {
    bw.writeU8(this.format);
    bw.writeBytes(this.address);
    return this;
  }

  read(br) {
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
    this.replacement = '.';
  }

  get type() {
    return types.NAPTR;
  }

  canonical() {
    this.replacement = this.replacement.toLowerCase();
    return this;
  }

  getSize(map) {
    let size = 0;
    size += 4;
    size += sizeString(this.flags);
    size += sizeString(this.service);
    size += sizeString(this.regexp);
    size += sizeName(this.replacement, map);
    return size;
  }

  write(bw, map) {
    bw.writeU16BE(this.order);
    bw.writeU16BE(this.preference);
    writeStringBW(bw, this.flags);
    writeStringBW(bw, this.service);
    writeStringBW(bw, this.regexp);
    writeNameBW(bw, this.replacement, map);
    return this;
  }

  read(br) {
    this.order = br.readU16BE();
    this.preference = br.readU16BE();
    this.flags = readStringBR(br);
    this.service = readStringBR(br);
    this.regexp = readStringBR(br);
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
    this.exchanger = '.';
  }

  get type() {
    return types.KX;
  }

  canonical() {
    this.exchanger = this.exchanger.toLowerCase();
    return this;
  }

  getSize(map) {
    return 2 + sizeName(this.exchanger, map);
  }

  write(bw, map) {
    bw.writeU16BE(this.preference);
    writeNameBW(bw, this.exchanger, map);
    return this;
  }

  read(br) {
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

  write(bw) {
    bw.writeU16BE(this.certType);
    bw.writeU16BE(this.keyTag);
    bw.writeU8(this.algorithm);
    bw.writeBytes(this.certificate);
    return this;
  }

  read(br) {
    this.certType = br.readU16BE();
    this.keyTag = br.readU16BE();
    this.algorithm = br.readU8();
    this.certificate = br.readBytes(br.left());
    return this;
  }

  getJSON() {
    const typeName = certTypesByVal[this.certType];
    const json = super.getJSON();

    if (typeName)
      json.typeName = typeName;

    json.algName = algToString(this.algorithm);

    return json;
  }

  toString() {
    const typeName = certTypesByVal[this.certType];
    const algName = algToString(this.algorithm);

    let str = super.toString();

    str += ' ';

    if (typeName)
      str += ` ; cert type = ${typeName}`;

    str += ` ; alg = ${algName}`;

    return str;
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
    this.prefixLen = 0;
    this.address = '::';
    this.prefix = '.';
  }

  get type() {
    return types.A6;
  }

  canonical() {
    this.prefix = this.prefix.toLowerCase();
    return this;
  }

  getSize(map) {
    const len = this.prefixLen;
    assert(len <= 128);

    let size = 0;

    size += 1;
    size += (128 - len + 7) / 8 | 0;

    if (len > 0)
      size += sizeName(this.prefix, map);

    return size;
  }

  write(bw, map) {
    const len = this.prefixLen;
    assert(len <= 128);

    bw.writeU8(len);

    const size = (128 - len + 7) / 8 | 0;
    const ip = IP.toBuffer(this.address);

    bw.copy(ip, 16 - size, 16);

    if (len > 0)
      writeNameBW(bw, this.prefix, map);

    return this;
  }

  read(br) {
    const len = Math.min(128, br.readU8());
    const size = (128 - len + 7) / 8 | 0;
    const buf = br.readBytes(size, true);
    const ip = POOL16;

    ip.fill(0x00, 0, 16 - size);
    ip.copy(buf, 16 - size);

    this.prefixLen = len;
    this.address = IP.toString(ip);

    if (len > 0)
      this.prefix = readNameBR(br);

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

  canonical() {
    // Note: not mentioned in RFC 4034.
    for (const opt of this.options)
      opt.canonical();
    return this;
  }

  getSize(map) {
    let size = 0;
    for (const opt of this.options)
      size += opt.getSize(map);
    return size;
  }

  write(bw, map) {
    for (const opt of this.options)
      opt.write(bw, map);
    return this;
  }

  read(br) {
    while (br.left())
      this.options.push(Option.read(br));
    return this;
  }

  toString() {
    return '';
  }

  fromString(str) {
    return this;
  }

  getJSON() {
    return {
      options: this.options.map(opt => opt.toJSON())
    };
  }

  fromJSON(json) {
    assert(json && typeof json === 'object');
    assert(Array.isArray(json.options));

    for (const opt of json.options)
      this.options.push(Option.fromJSON(opt));

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
    this.items = [];
  }

  get type() {
    return types.APL;
  }

  getSize() {
    let size = 0;

    for (const ap of this.items)
      size += ap.getSize();

    return size;
  }

  write(bw) {
    for (const ap of this.items)
      ap.write(bw);

    return this;
  }

  read(br) {
    while (br.left())
      this.items.push(AP.read(br));

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

  write(bw) {
    bw.writeU16BE(this.keyTag);
    bw.writeU8(this.algorithm);
    bw.writeU8(this.digestType);
    bw.writeBytes(this.digest);
    return this;
  }

  read(br) {
    this.keyTag = br.readU16BE();
    this.algorithm = br.readU8();
    this.digestType = br.readU8();
    this.digest = br.readBytes(br.left());
    return this;
  }

  getJSON() {
    const json = super.getJSON();
    json.algName = algToString(this.algorithm);
    json.hashName = hashToString(this.digestType);
    return json;
  }

  toString() {
    const algName = algToString(this.algorithm);
    const hashName = hashToString(this.digestType);

    let str = super.toString();

    // Mimic `delv`.
    str += ' ';
    str += ` ; alg = ${algName}`;
    str += ` ; hash = ${hashName}`;

    return str;
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
    this.digestType = 0;
    this.fingerprint = DUMMY;
  }

  get type() {
    return types.SSHFP;
  }

  getSize() {
    return 2 + this.fingerprint.length;
  }

  write(bw) {
    bw.writeU8(this.algorithm);
    bw.writeU8(this.digestType);
    bw.writeBytes(this.fingerprint);
    return this;
  }

  read(br) {
    this.algorithm = br.readU8();
    this.digestType = br.readU8();
    this.fingerprint = br.readBytes(br.left());
    return this;
  }

  getJSON() {
    const algName = sshAlgsByVal[this.algorithm];
    const hashName = sshHashesByVal[this.digestType];
    const json = super.getJSON();

    if (algName)
      json.algName = algName;

    if (hashName)
      json.hashName = hashName;

    return json;
  }

  toString() {
    const algName = sshAlgsByVal[this.algorithm];
    const hashName = sshHashesByVal[this.digestType];

    let str = super.toString();

    str += ' ';

    if (algName)
      str += ` ; alg = ${algName}`;

    if (hashName)
      str += ` ; hash = ${hashName}`;

    return str;
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
    this.gatewayType = 1;
    this.algorithm = 0;
    this.target = '0.0.0.0';
    this.publicKey = DUMMY;
  }

  get type() {
    return types.IPSECKEY;
  }

  canonical() {
    // Note: not mentioned in RFC 4034.
    if (this.gatewayType === 3)
      this.target = this.target.toLowerCase();
    return this;
  }

  getSize(map) {
    let size = 3;

    switch (this.gatewayType) {
      case 1:
        size += 4;
        break;
      case 2:
        size += 16;
        break;
      case 3:
        size += sizeName(this.target, map);
        break;
    }

    size += this.publicKey.length;

    return size;
  }

  write(bw, map) {
    bw.writeU8(this.precedence);
    bw.writeU8(this.gatewayType);
    bw.writeU8(this.algorithm);

    switch (this.gatewayType) {
      case 1: {
        writeIP(bw, this.target, 4);
        break;
      }
      case 2: {
        writeIP(bw, this.target, 16);
        break;
      }
      case 3:
        writeNameBW(bw, this.target, map);
        break;
    }

    bw.writeBytes(this.publicKey);

    return this;
  }

  read(br) {
    this.precedence = br.readU8();
    this.gatewayType = br.readU8();
    this.algorithm = br.readU8();

    switch (this.gatewayType) {
      case 1:
        this.target = readIP(br, 4);
        break;
      case 2:
        this.target = readIP(br, 16);
        break;
      case 3:
        this.target = readNameBR(br);
        break;
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

  canonical() {
    this.nextDomain = this.nextDomain.toLowerCase();
    return this;
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

  getSize(map) {
    let size = 0;
    size += sizeName(this.nextDomain, map);
    size += this.typeBitmap.length;
    return size;
  }

  write(bw, map) {
    writeNameBW(bw, this.nextDomain, map);
    bw.writeBytes(this.typeBitmap);
    return this;
  }

  read(br) {
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

  write(bw) {
    bw.writeBytes(this.digest);
    return this;
  }

  read(br) {
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
    let size = 0;
    size += 6;
    size += this.salt.length;
    size += this.nextDomain.length;
    size += this.typeBitmap.length;
    return size;
  }

  write(bw) {
    bw.writeU8(this.hash);
    bw.writeU8(this.flags);
    bw.writeU16BE(this.iterations);
    bw.writeU8(this.salt.length);
    bw.writeBytes(this.salt);
    bw.writeU8(this.nextDomain.length);
    bw.writeBytes(this.nextDomain);
    bw.writeBytes(this.typeBitmap);
    return this;
  }

  read(br) {
    this.hash = br.readU8();
    this.flags = br.readU8();
    this.iterations = br.readU16BE();
    this.salt = br.readBytes(br.readU8());
    this.nextDomain = br.readBytes(br.readU8());
    this.typeBitmap = br.readBytes(br.left());
    return this;
  }

  getJSON() {
    const hashName = nsecHashesByVal[this.hash];
    const json = super.getJSON();

    if (hashName)
      json.hashName = hashName;

    return json;
  }

  toString() {
    const hashName = nsecHashesByVal[this.hash];

    let str = super.toString();

    str += ' ';

    if (hashName)
      str += ` ; hash = ${hashName}`;

    return str;
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

  write(bw) {
    bw.writeU8(this.hash);
    bw.writeU8(this.flags);
    bw.writeU16BE(this.iterations);
    bw.writeU8(this.salt.length);
    bw.writeBytes(this.salt);
    return this;
  }

  read(br) {
    this.hash = br.readU8();
    this.flags = br.readU8();
    this.iterations = br.readU16BE();
    this.salt = br.readBytes(br.readU8());
    return this;
  }

  getJSON() {
    const hashName = nsecHashesByVal[this.hash];
    const json = super.getJSON();

    if (hashName)
      json.hashName = hashName;

    return json;
  }

  toString() {
    const hashName = nsecHashesByVal[this.hash];

    let str = super.toString();

    str += ' ';

    if (hashName)
      str += ` ; hash = ${hashName}`;

    return str;
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

  write(bw) {
    bw.writeU8(this.usage);
    bw.writeU8(this.selector);
    bw.writeU8(this.matchingType);
    bw.writeBytes(this.certificate);
    return this;
  }

  read(br) {
    this.usage = br.readU8();
    this.selector = br.readU8();
    this.matchingType = br.readU8();
    this.certificate = br.readBytes(br.left());
    return this;
  }

  getJSON() {
    const usageName = usagesByVal[this.usage];
    const selectorName = selectorsByVal[this.selector];
    const matchingTypeName = matchingTypesByVal[this.matchingType];
    const json = super.getJSON();

    if (usageName)
      json.usageName = usageName;

    if (selectorName)
      json.selectorName = selectorName;

    if (matchingTypeName)
      json.matchingTypeName = matchingTypeName;

    return json;
  }

  toString() {
    const usageName = usagesByVal[this.usage];
    const selectorName = selectorsByVal[this.selector];
    const matchingTypeName = matchingTypesByVal[this.matchingType];

    let str = super.toString();

    str += ' ';

    if (usageName)
      str += ` ; usage = ${usageName}`;

    if (selectorName)
      str += ` ; selector = ${selectorName}`;

    if (matchingTypeName)
      str += ` ; matching type = ${matchingTypeName}`;

    return str;
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
    this.servers = [];
  }

  get type() {
    return types.HIP;
  }

  canonical() {
    // Note: not mentioned in RFC 4034.
    for (let i = 0; i < this.servers.length; i++)
      this.servers[i] = this.servers[i].toLowerCase();

    return this;
  }

  getSize(map) {
    let size = 4;
    size += this.hit.length;
    size += this.publicKey.length;
    for (const name of this.servers)
      size += sizeName(name, map);
    return size;
  }

  write(bw, map) {
    bw.writeU8(this.hit.length);
    bw.writeU8(this.algorithm);
    bw.writeU16BE(this.publicKey.length);
    bw.writeBytes(this.hit);
    bw.writeBytes(this.publicKey);
    for (const name of this.servers)
      writeNameBW(bw, name, map);
    return this;
  }

  read(br) {
    const hitLen = br.readU8();

    this.algorithm = br.readU8();

    const keyLen = br.readU16BE();

    this.hit = br.readBytes(hitLen);
    this.publicKey = br.readBytes(keyLen);

    while (br.left())
      this.servers.push(readNameBR(br));

    return this;
  }
}

/**
 * NINFO Record
 * Zone Status Information (proposed)
 * @see https://www.iana.org/assignments/dns-parameters/NINFO/ninfo-completed-template
 * @see https://tools.ietf.org/html/draft-reid-dnsext-zs-01
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
      size += sizeString(zs);
    return size;
  }

  write(bw) {
    for (const zs of this.zsData)
      writeStringBW(bw, zs);
    return this;
  }

  read(br) {
    while (br.left())
      this.zsData.push(readStringBR(br));
    return this;
  }
}

/**
 * RKEY Record
 * R Key Record (proposed)
 * @see https://www.iana.org/assignments/dns-parameters/RKEY/rkey-completed-template
 * @see https://tools.ietf.org/html/draft-reid-dnsext-rkey-00
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
 * @see https://tools.ietf.org/html/draft-wijngaards-dnsop-trust-history-02
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

  canonical() {
    // Note: not mentioned in RFC 4034.
    this.prevName = this.prevName.toLowerCase();
    this.nextName = this.nextName.toLowerCase();
    return this;
  }

  getSize(map) {
    let size = 0;
    size += sizeName(this.prevName, map);
    size += sizeName(this.nextName, map);
    return size;
  }

  write(bw, map) {
    writeNameBW(bw, this.prevName, map);
    writeNameBW(bw, this.nextName, map);
    return this;
  }

  read(br) {
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

  write(bw) {
    bw.writeBytes(this.publicKey);
    return this;
  }

  read(br) {
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

  write(bw) {
    bw.writeU32BE(this.serial);
    bw.writeU16BE(this.flags);
    bw.writeBytes(this.typeBitmap);
    return this;
  }

  read(br) {
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
    return sizeString(this.uinfo);
  }

  write(bw) {
    writeStringBW(bw, this.uinfo);
    return this;
  }

  read(br) {
    this.uinfo = readStringBR(br);
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

  write(bw) {
    bw.writeU32BE(this.uid);
    return this;
  }

  read(br) {
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

  write(bw) {
    bw.writeU32BE(this.gid);
    return this;
  }

  read(br) {
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

  write(bw) {
    bw.writeU16BE(this.preference);
    bw.writeBytes(this.nodeID);
    return this;
  }

  read(br) {
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
    this.locator32 = DUMMY4;
  }

  get type() {
    return types.L32;
  }

  getSize() {
    return 6;
  }

  write(bw) {
    bw.writeU16BE(this.preference);
    bw.writeBytes(this.locator32);
    return this;
  }

  read(br) {
    this.preference = br.readU16BE();
    this.locator32 = br.readBytes(4);
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

  write(bw) {
    bw.writeU16BE(this.preference);
    bw.writeBytes(this.locator64);
    return this;
  }

  read(br) {
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
    this.fqdn = '.';
  }

  get type() {
    return types.LP;
  }

  canonical() {
    // Note: not mentioned in RFC 4034.
    this.fqdn = this.fqdn.toLowerCase();
    return this;
  }

  getSize(map) {
    return 2 + sizeName(this.fqdn, map);
  }

  write(bw, map) {
    bw.writeU16BE(this.preference);
    writeNameBW(bw, this.fqdn, map);
    return this;
  }

  read(br) {
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

  get type() {
    return types.EUI48;
  }

  getSize() {
    return 6;
  }

  write(bw) {
    bw.writeBytes(this.address);
    return this;
  }

  read(br) {
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

  get type() {
    return types.EUI64;
  }

  getSize() {
    return 8;
  }

  write(bw) {
    bw.writeBytes(this.address);
    return this;
  }

  read(br) {
    this.address = br.readBytes(8);
    return this;
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
    this.algorithm = '.';
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

  canonical() {
    // Note: not mentioned in RFC 4034.
    this.algorithm = this.algorithm.toLowerCase();
    return this;
  }

  getSize(map) {
    let size = 0;
    size += sizeName(this.algorithm, map);
    size += 16;
    size += this.key.length;
    size += this.other.length;
    return size;
  }

  write(bw, map) {
    writeNameBW(bw, this.algorithm, map);
    bw.writeU32BE(this.inception);
    bw.writeU32BE(this.expiration);
    bw.writeU16BE(this.mode);
    bw.writeU16BE(this.error);
    bw.writeU16BE(this.key.length);
    bw.writeBytes(this.key);
    bw.writeU16BE(this.other.length);
    bw.writeBytes(this.other);
    return this;
  }

  read(br) {
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
    this.algorithm = '.';
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

  canonical() {
    // Note: not mentioned in RFC 4034.
    this.algorithm = this.algorithm.toLowerCase();
    return this;
  }

  getSize(map) {
    let size = 16;
    size += sizeName(this.algorithm, map);
    size += this.mac.length;
    size += this.other.length;
    return size;
  }

  write(bw, map) {
    writeNameBW(bw, this.algorithm, map);
    bw.writeU16BE((this.timeSigned / 0x100000000) >>> 0);
    bw.writeU32BE(this.timeSigned >>> 0);
    bw.writeU16BE(this.fudge);
    bw.writeU16BE(this.mac.length);
    bw.writeBytes(this.mac);
    bw.writeU16BE(this.origID);
    bw.writeU16BE(this.error);
    bw.writeU16BE(this.other.length);
    bw.writeBytes(this.other);
    return this;
  }

  read(br) {
    this.algorithm = readNameBR(br);
    this.timeSigned = br.readU16BE() * 0x100000000 + br.readU32BE();
    this.fudge = br.readU16BE();
    this.mac = br.readBytes(br.readU16BE());
    this.origID = br.readU16BE();
    this.error = br.readU16BE();
    this.other = br.readBytes(br.readU16BE());
    return this;
  }

  getJSON() {
    const algorithm = this.algorithm.toLowerCase();
    const algName = tsigAlgsByVal[algorithm];
    const json = super.getJSON();

    if (algName)
      json.algName = algName;

    return json;
  }

  toString() {
    const algorithm = this.algorithm.toLowerCase();
    const algName = tsigAlgsByVal[algorithm];

    let str = super.toString();

    str += ' ';

    if (algName)
      str += ` ; alg = ${algName}`;

    return str;
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
    return 4 + sizeRawString(this.target);
  }

  write(bw) {
    bw.writeU16BE(this.priority);
    bw.writeU16BE(this.weight);
    writeRawStringBW(bw, this.target);
    return this;
  }

  read(br) {
    this.priority = br.readU16BE();
    this.weight = br.readU16BE();
    this.target = readRawStringBR(br, br.left(), true);
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
    let size = 0;
    size += 1;
    size += sizeString(this.tag);
    size += sizeRawString(this.value);
    return size;
  }

  write(bw) {
    bw.writeU8(this.flag);
    writeStringBW(bw, this.tag);
    writeRawStringBW(bw, this.value);
    return this;
  }

  read(br) {
    this.flag = br.readU8();
    this.tag = readStringBR(br, true);
    this.value = readRawStringBR(br, br.left());
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
 * DOA Record
 * Digital Object Architecture Record
 * @see https://www.ietf.org/archive/id/draft-durand-doa-over-dns-03.txt
 */

class DOARecord extends RecordData {
  constructor() {
    super();
    this.enterprise = 0;
    this.doa = 0;
    this.location = 0;
    this.mediaType = '';
    this.data = DUMMY;
  }

  get type() {
    return types.DOA;
  }

  getSize() {
    let size = 0;
    size += 9;
    size += sizeString(this.mediaType);
    size += this.data.length;
    return size;
  }

  write(bw) {
    bw.writeU32BE(this.enterprise);
    bw.writeU32BE(this.doa);
    bw.writeU8(this.location);
    writeStringBW(bw, this.mediaType);
    bw.writeBytes(this.data);
    return this;
  }

  read(br) {
    this.enterprise = br.readU32BE();
    this.doa = br.readU32BE();
    this.location = br.readU8();
    this.mediaType = readStringBR(br);
    this.data = br.readBytes(br.left());
    return this;
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

  write(bw) {
    bw.writeU16BE(this.keyTag);
    bw.writeU8(this.algorithm);
    bw.writeU8(this.digestType);
    bw.writeBytes(this.digest);
    return this;
  }

  read(br) {
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
 * Option Field
 * @see https://tools.ietf.org/html/rfc6891#section-6.1
 */

class Option extends Struct {
  constructor() {
    super();
    this.code = 0;
    this.option = new UNKNOWNOption();
  }

  canonical() {
    // Note: not mentioned in RFC 4034.
    this.option.canonical();
    return this;
  }

  getSize(map) {
    return 4 + this.option.getSize(map);
  }

  write(bw, map) {
    bw.writeU16BE(this.code);
    bw.writeU16BE(0);

    const off = bw.offset;

    this.option.write(bw, map);

    const size = bw.offset - off;

    bio.writeU16BE(bw.data, size, off - 2);

    return this;
  }

  read(br) {
    this.code = br.readU16BE();

    const size = br.readU16BE();
    const child = br.readChild(size);

    this.option = readOption(this.code, child);

    return this;
  }

  toString() {
    const code = optionToString(this.code);
    const isUnknown = optionsByVal[this.code] == null;

    let body = this.option.toString();

    if (isUnknown) {
      assert(this.option.code === options.RESERVED);
      const size = this.options.getSize().toString(10);
      body = `\\# ${size} ${body}`;
    }

    return `${code}: ${body}`;
  }

  fromString(str) {
    const scan = lazy('./internal/scan');
    const op = scan.parseOption(exports, str);
    return this.inject(op);
  }

  getJSON() {
    return {
      code: optionToString(this.code),
      option: this.option.toJSON()
    };
  }

  fromJSON(json) {
    assert(json && typeof json === 'object');
    assert(json.option && typeof json.option === 'object');

    const code = stringToOption(json.code);
    const Option = optsByVal[code];

    let option;
    if (options[json.code] == null) {
      const data = util.parseHex(json.option.data);

      if (Option)
        option = Option.decode(data);
      else
        option = UNKNOWNOption.decode(data);
    } else {
      if (!Option)
        throw new Error(`Unknown option code: ${json.code}.`);

      option = Option.fromJSON(json.option);
    }

    this.code = code;
    this.option = option;

    return this;
  }
}

/**
 * OptionData
 */

class OptionData extends Struct {
  constructor() {
    super();
  }

  get code() {
    return options.RESERVED;
  }

  _schema() {
    const schema = lazy('./internal/schema');
    const s = schema.options[this.code];

    if (!s)
      return schema.options[options.RESERVED];

    return s;
  }

  canonical() {
    return this;
  }

  toString() {
    const schema = lazy('./internal/schema');
    return schema.toString(exports, this, this._schema());
  }

  fromString(str) {
    const scan = lazy('./internal/scan');
    const od = scan.parseOptionData(exports, this.code, str);
    return this.inject(od);
  }

  getJSON() {
    const schema = lazy('./internal/schema');
    return schema.toJSON(exports, this, this._schema());
  }

  fromJSON(json) {
    const schema = lazy('./internal/schema');
    return schema.fromJSON(exports, this, this._schema(), json);
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
    return options.RESERVED;
  }

  getSize() {
    return this.data.length;
  }

  write(bw) {
    bw.writeBytes(this.data);
    return this;
  }

  read(br) {
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

  write(bw) {
    bw.writeU16BE(this.version);
    bw.writeU16BE(this.opcode);
    bw.writeU16BE(this.error);
    bw.writeBytes(this.id);
    bw.writeU32BE(this.leaseLife);
    return this;
  }

  read(br) {
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

  write(bw) {
    bw.writeU32BE(this.lease);
    return this;
  }

  read(br) {
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

  write(bw) {
    bw.writeBytes(this.nsid);
    return this;
  }

  read(br) {
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

  write(bw) {
    bw.writeBytes(this.algCode);
    return this;
  }

  read(br) {
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
    this.address = DUMMY;
  }

  get code() {
    return options.SUBNET;
  }

  // SOURCE PREFIX-LENGTH represents a number of bits.
  // The actual data must be padded to the end of the next octet.
  getAddressSize() {
    return Math.ceil(this.sourceNetmask / 8);
  }

  getSize() {
    return 4 + this.getAddressSize();
  }

  write(bw) {
    assert(this.address.length === this.getAddressSize());
    bw.writeU16BE(this.family);
    bw.writeU8(this.sourceNetmask);
    bw.writeU8(this.sourceScope);
    bw.writeBytes(this.address);

    return this;
  }

  read(br) {
    this.family = br.readU16BE();
    this.sourceNetmask = br.readU8();
    this.sourceScope = br.readU8();
    this.address = br.readBytes(this.getAddressSize());

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

  write(bw) {
    bw.writeU32BE(this.expire);
    return this;
  }

  read(br) {
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

  write(bw) {
    bw.writeBytes(this.cookie);
    return this;
  }

  read(br) {
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

  write(bw) {
    bw.writeU16BE(this.length);
    bw.writeU16BE(this.timeout);
    return this;
  }

  read(br) {
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

  write(bw) {
    bw.writeBytes(this.padding);
    return this;
  }

  read(br) {
    this.padding = br.readBytes(br.left());
    return this;
  }
}

/**
 * CHAIN Option
 * EDNS Chain Option
 * @see https://tools.ietf.org/html/rfc7901
 */

class CHAINOption extends OptionData {
  constructor() {
    super();
    this.trustPoint = '.';
  }

  get code() {
    return options.CHAIN;
  }

  canonical() {
    // Note: not mentioned in RFC 4034.
    this.trustPoint = this.trustPoint.toLowerCase();
    return this;
  }

  getSize(map) {
    return sizeName(this.trustPoint, map);
  }

  write(bw, map) {
    writeNameBW(bw, this.trustPoint, map);
    return this;
  }

  read(br) {
    this.trustPoint = readNameBR(br);
    return this;
  }
}

/**
 * KEYTAG Option
 * EDNS Key Tag Option
 * @see https://tools.ietf.org/html/rfc8145
 */

class KEYTAGOption extends OptionData {
  constructor() {
    super();
    this.tags = [];
  }

  get code() {
    return options.KEYTAG;
  }

  getSize() {
    return this.tags.length * 2;
  }

  write(bw) {
    for (const tag of this.tags)
      bw.writeU16BE(tag);
    return this;
  }

  read(br) {
    while (br.left())
      this.tags.push(br.readU16BE());
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

  write(bw) {
    bw.writeBytes(this.data);
    return this;
  }

  read(br) {
    this.data = br.readBytes(br.left());
    return this;
  }
}

/**
 * Address Prefix
 * Used for APL Records
 * @see https://tools.ietf.org/html/rfc3123
 */

class AP extends Struct {
  constructor() {
    super();
    this.family = 1;
    this.prefix = 0;
    this.n = 0;
    this.afd = DUMMY4;
  }

  getSize() {
    return 4 + this.afd.length;
  }

  write(bw) {
    bw.writeU16BE(this.family);
    bw.writeU8(this.prefix);
    bw.writeU8((this.n << 7) | this.afd.length);
    bw.writeBytes(this.afd);
    return this;
  }

  read(br) {
    const family = br.readU16BE();
    const prefix = br.readU8();

    const field = br.readU8();
    const n = field >>> 7;
    const len = field & 0x7f;
    const afd = br.readBytes(len);

    this.family = family;
    this.prefix = prefix;
    this.n = n;
    this.afd = afd;

    return this;
  }

  getJSON() {
    return {
      family: this.family,
      prefix: this.prefix,
      n: this.n,
      afd: this.afd.toString('hex')
    };
  }

  fromJSON(json) {
    assert(json && typeof json === 'object');
    assert((json.family & 0xff) === json.family);
    assert((json.prefix & 0xff) === json.prefix);
    assert((json.n & 1) === json.n);

    this.family = json.family;
    this.prefix = json.prefix;
    this.n = json.n;
    this.afd = util.parseHex(json.afd);

    return this;
  }

  getAFD() {
    if (this.family === 1) {
      const afd = util.padRight(this.afd, 4);
      return IP.toString(afd);
    }

    if (this.family === 2) {
      const afd = util.padRight(this.afd, 16);

      if (IP.isIPv4(afd))
        return `::ffff:${IP.toString(afd)}`;

      return IP.toString(afd);
    }

    return this.afd.toString('hex');
  }

  setAFD(addr) {
    if (this.family === 1) {
      const ip = IP.toBuffer(addr);

      if (!IP.isIPv4(ip))
        throw new Error('Invalid AFD.');

      this.afd = ip;

      return this;
    }

    if (this.family === 2) {
      this.afd = IP.toBuffer(addr);
      return this;
    }

    this.afd = util.parseHex(addr);

    return this;
  }

  toString() {
    let str = '';

    if (this.n)
      str += '!';

    str += this.family.toString(10);
    str += ':';
    str += this.getAFD();
    str += '/';
    str += this.prefix;

    return str;
  }

  fromString(str) {
    assert(typeof str === 'string');
    assert(str.length <= 265);

    let n = 0;

    // {[!]afi:address/prefix}
    if (str.length > 0 && str[0] === '!') {
      str = str.substring(1);
      n = 1;
    }

    const colon = str.indexOf(':');
    assert(colon !== -1);

    const afi = str.substring(0, colon);
    const rest = str.substring(colon + 1);

    const slash = rest.indexOf('/');
    assert(slash !== -1);

    const addr = rest.substring(0, slash);
    const prefix = rest.substring(slash + 1);

    this.family = util.parseU8(afi);
    this.prefix = util.parseU8(prefix);
    this.n = n;
    this.setAFD(addr);

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
  TKEY: TKEYRecord,
  TSIG: TSIGRecord,
  URI: URIRecord,
  CAA: CAARecord,
  AVC: AVCRecord,
  DOA: DOARecord,
  IXFR: null,
  AXFR: null,
  MAILB: null,
  MAILA: null,
  ANY: null,
  TA: TARecord,
  DLV: DLVRecord,
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
  [types.TKEY]: TKEYRecord,
  [types.TSIG]: TSIGRecord,
  [types.URI]: URIRecord,
  [types.CAA]: CAARecord,
  [types.AVC]: AVCRecord,
  [types.DOA]: DOARecord,
  [types.IXFR]: null,
  [types.AXFR]: null,
  [types.MAILB]: null,
  [types.MAILA]: null,
  [types.ANY]: null,
  [types.TA]: TARecord,
  [types.DLV]: DLVRecord,
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
  CHAIN: CHAINOption,
  KEYTAG: KEYTAGOption,
  LOCAL: LOCALOption,
  LOCALSTART: LOCALOption,
  LOCALEND: LOCALOption
};

/**
 * EDNS0 Option Classes By Value
 * @const {Object}
 */

optsByVal = {
  [options.RESERVED]: UNKNOWNOption,
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
  [options.CHAIN]: CHAINOption,
  [options.KEYTAG]: KEYTAGOption,
  [options.LOCAL]: LOCALOption,
  [options.LOCALSTART]: LOCALOption,
  [options.LOCALEND]: LOCALOption
};

/*
 * Decode
 */

function decodeData(type, data) {
  return readData(type, bio.read(data));
}

function readData(type, br) {
  assert((type & 0xffff) === type);

  switch (type) {
    case types.A:
      return ARecord.read(br);
    case types.NS:
      return NSRecord.read(br);
    case types.MD:
      return MDRecord.read(br);
    case types.MF:
      return MFRecord.read(br);
    case types.CNAME:
      return CNAMERecord.read(br);
    case types.SOA:
      return SOARecord.read(br);
    case types.MB:
      return MBRecord.read(br);
    case types.MG:
      return MGRecord.read(br);
    case types.MR:
      return MRRecord.read(br);
    case types.NULL:
      return NULLRecord.read(br);
    case types.WKS:
      return WKSRecord.read(br);
    case types.PTR:
      return PTRRecord.read(br);
    case types.HINFO:
      return HINFORecord.read(br);
    case types.MINFO:
      return MINFORecord.read(br);
    case types.MX:
      return MXRecord.read(br);
    case types.TXT:
      return TXTRecord.read(br);
    case types.RP:
      return RPRecord.read(br);
    case types.AFSDB:
      return AFSDBRecord.read(br);
    case types.X25:
      return X25Record.read(br);
    case types.ISDN:
      return ISDNRecord.read(br);
    case types.RT:
      return RTRecord.read(br);
    case types.NSAP:
      return NSAPRecord.read(br);
    case types.NSAPPTR:
      return NSAPPTRRecord.read(br);
    case types.SIG:
      return SIGRecord.read(br);
    case types.KEY:
      return KEYRecord.read(br);
    case types.PX:
      return PXRecord.read(br);
    case types.GPOS:
      return GPOSRecord.read(br);
    case types.AAAA:
      return AAAARecord.read(br);
    case types.LOC:
      return LOCRecord.read(br);
    case types.NXT:
      return NXTRecord.read(br);
    case types.EID:
      return EIDRecord.read(br);
    case types.NIMLOC:
      return NIMLOCRecord.read(br);
    case types.SRV:
      return SRVRecord.read(br);
    case types.ATMA:
      return ATMARecord.read(br);
    case types.NAPTR:
      return NAPTRRecord.read(br);
    case types.KX:
      return KXRecord.read(br);
    case types.CERT:
      return CERTRecord.read(br);
    case types.A6:
      return A6Record.read(br);
    case types.DNAME:
      return DNAMERecord.read(br);
    case types.OPT:
      return OPTRecord.read(br);
    case types.APL:
      return APLRecord.read(br);
    case types.DS:
      return DSRecord.read(br);
    case types.SSHFP:
      return SSHFPRecord.read(br);
    case types.IPSECKEY:
      return IPSECKEYRecord.read(br);
    case types.RRSIG:
      return RRSIGRecord.read(br);
    case types.NSEC:
      return NSECRecord.read(br);
    case types.DNSKEY:
      return DNSKEYRecord.read(br);
    case types.DHCID:
      return DHCIDRecord.read(br);
    case types.NSEC3:
      return NSEC3Record.read(br);
    case types.NSEC3PARAM:
      return NSEC3PARAMRecord.read(br);
    case types.TLSA:
      return TLSARecord.read(br);
    case types.SMIMEA:
      return SMIMEARecord.read(br);
    case types.HIP:
      return HIPRecord.read(br);
    case types.NINFO:
      return NINFORecord.read(br);
    case types.RKEY:
      return RKEYRecord.read(br);
    case types.TALINK:
      return TALINKRecord.read(br);
    case types.CDS:
      return CDSRecord.read(br);
    case types.CDNSKEY:
      return CDNSKEYRecord.read(br);
    case types.OPENPGPKEY:
      return OPENPGPKEYRecord.read(br);
    case types.CSYNC:
      return CSYNCRecord.read(br);
    case types.SPF:
      return SPFRecord.read(br);
    case types.UINFO:
      return UINFORecord.read(br);
    case types.UID:
      return UIDRecord.read(br);
    case types.GID:
      return GIDRecord.read(br);
    case types.UNSPEC:
      return UNSPECRecord.read(br);
    case types.NID:
      return NIDRecord.read(br);
    case types.L32:
      return L32Record.read(br);
    case types.L64:
      return L64Record.read(br);
    case types.LP:
      return LPRecord.read(br);
    case types.EUI48:
      return EUI48Record.read(br);
    case types.EUI64:
      return EUI64Record.read(br);
    case types.TKEY:
      return TKEYRecord.read(br);
    case types.TSIG:
      return TSIGRecord.read(br);
    case types.URI:
      return URIRecord.read(br);
    case types.CAA:
      return CAARecord.read(br);
    case types.AVC:
      return AVCRecord.read(br);
    case types.DOA:
      return DOARecord.read(br);
    case types.TA:
      return TARecord.read(br);
    case types.DLV:
      return DLVRecord.read(br);
    default:
      return UNKNOWNRecord.read(br);
  }
}

function decodeOption(code, data) {
  return readOption(code, bio.read(data));
}

function readOption(code, br) {
  assert((code & 0xffff) === code);

  switch (code) {
    case options.LLQ:
      return LLQOption.read(br);
    case options.UL:
      return ULOption.read(br);
    case options.NSID:
      return NSIDOption.read(br);
    case options.DAU:
      return DAUOption.read(br);
    case options.DHU:
      return DHUOption.read(br);
    case options.N3U:
      return N3UOption.read(br);
    case options.SUBNET:
      return SUBNETOption.read(br);
    case options.EXPIRE:
      return EXPIREOption.read(br);
    case options.COOKIE:
      return COOKIEOption.read(br);
    case options.TCPKEEPALIVE:
      return TCPKEEPALIVEOption.read(br);
    case options.PADDING:
      return PADDINGOption.read(br);
    case options.CHAIN:
      return CHAINOption.read(br);
    case options.KEYTAG:
      return KEYTAGOption.read(br);
    default:
      if (code >= options.LOCALSTART && code <= options.LOCALEND)
        return LOCALOption.read(br);
      return UNKNOWNOption.read(br);
  }
}

function fromZone(text, origin, file) {
  assert(typeof text === 'string');
  const scan = lazy('./internal/scan');
  return scan.parseZone(exports, text, origin, file);
}

function toZone(records) {
  assert(Array.isArray(records));

  let text = '';

  for (const rr of records) {
    assert(rr instanceof Record);
    text += rr.toString();
    text += '\n';
  }

  return text;
}

function truncate(msg, max) {
  assert(Buffer.isBuffer(msg));
  assert(msg.length >= 12);
  assert((max >>> 0) === max);
  assert(max >= 12);

  if (msg.length <= max)
    return msg;

  const br = bio.read(msg);

  br.seek(2);

  const bits = br.readU16BE();

  const counts = [
    br.readU16BE(),
    br.readU16BE(),
    br.readU16BE(),
    br.readU16BE()
  ];

  let last = br.offset;

  for (let s = 0; s < 4; s++) {
    const count = counts[s];

    let i = 0;
    let j = 0;

    while (br.offset <= max) {
      last = br.offset;
      j = i;

      if (i === count)
        break;

      i += 1;

      readNameBR(br);

      // Question.
      if (s === 0) {
        br.seek(4);
        continue;
      }

      // Record.
      br.seek(8);
      br.seek(br.readU16BE());
    }

    counts[s] = j;
  }

  bio.writeU16BE(msg, bits | flags.TC, 2);
  bio.writeU16BE(msg, counts[0], 4);
  bio.writeU16BE(msg, counts[1], 6);
  bio.writeU16BE(msg, counts[2], 8);
  bio.writeU16BE(msg, counts[3], 10);

  return msg.slice(0, last);
}

function isRSA(algorithm) {
  assert((algorithm & 0xff) === algorithm);

  switch (algorithm) {
    case algs.RSAMD5:
    case algs.RSASHA1:
    case algs.RSASHA1NSEC3SHA1:
    case algs.RSASHA256:
    case algs.RSASHA512:
      return true;
    default:
      return false;
  }
}

function rsaBits(buf) {
  assert(Buffer.isBuffer(buf));

  if (buf.length === 0)
    return 0;

  let explen = buf[0];
  let keyoff = 1;

  if (explen === 0) {
    if (buf.length < 3)
      return 0;
    explen = (buf[1] << 8) | buf[2];
    keyoff = 3;
  }

  if (buf.length < keyoff + explen)
    return 0;

  const e = buf.slice(keyoff, keyoff + explen);
  const n = buf.slice(keyoff + explen);

  return [countBits(n), countBits(e)];
}

function countBits(buf) {
  assert(Buffer.isBuffer(buf));

  let i = 0;

  for (; i < buf.length; i++) {
    if (buf[i] !== 0x00)
      break;
  }

  let bits = (buf.length - i) * 8;

  if (bits === 0)
    return 0;

  bits -= 8;

  let oct = buf[i];

  while (oct) {
    bits += 1;
    oct >>>= 1;
  }

  return bits;
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

exports.Message = Message;
exports.EDNS = EDNS;
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
exports.TKEYRecord = TKEYRecord;
exports.TSIGRecord = TSIGRecord;
exports.URIRecord = URIRecord;
exports.CAARecord = CAARecord;
exports.AVCRecord = AVCRecord;
exports.DOARecord = DOARecord;
exports.TARecord = TARecord;
exports.DLVRecord = DLVRecord;

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
exports.CHAINOption = CHAINOption;
exports.KEYTAGOption = KEYTAGOption;
exports.LOCALOption = LOCALOption;

exports.AP = AP;

exports.records = records;
exports.recordsByVal = recordsByVal;
exports.opts = opts;
exports.optsByVal = optsByVal;

exports.decodeData = decodeData;
exports.readData = readData;

exports.decodeOption = decodeOption;
exports.readOption = readOption;

exports.fromZone = fromZone;
exports.toZone = toZone;
exports.truncate = truncate;
