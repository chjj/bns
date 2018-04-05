/*!
 * scan.js - zone file parsing for bns
 * Copyright (c) 2018, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bns
 *
 * Parts of this software are based on miekg/dns:
 *   https://github.com/miekg/dns/blob/master/scan.go
 *   https://github.com/miekg/dns/blob/master/scan_rr.go
 *   https://github.com/miekg/dns/blob/master/generate.go
 */

'use strict';

const assert = require('assert');
const fs = require('bfile');
const Path = require('path');
const encoding = require('./encoding');
const constants = require('./constants');
const schema = require('./schema');
const util = require('./util');
const wire = require('./wire');

const {
  types,
  classes,
  stringToType,
  stringToClass
} = constants;

/*
 * Constants
 */

const MAX_TOKEN = 2048;
const MAX_INCLUDES = 7;
const DEFAULT_TTL = 3600;

const tokens = {
  EOF: 0,
  STRING: 1,
  BLANK: 2,
  QUOTE: 3,
  NEWLINE: 4,
  RRTYPE: 5,
  OWNER: 6,
  CLASS: 7,
  DIR_ORIGIN: 8,
  DIR_TTL: 9,
  DIR_INCLUDE: 10,
  DIR_GENERATE: 11,
  VALUE: 12,
  KEY: 13
};

const states = {
  EXPECT_OWNER_DIR: 0,
  EXPECT_OWNER_BL: 1,
  EXPECT_ANY: 2,
  EXPECT_ANY_NO_CLASS: 3,
  EXPECT_ANY_NO_CLASS_BL: 4,
  EXPECT_ANY_NO_TTL: 5,
  EXPECT_ANY_NO_TTL_BL: 6,
  EXPECT_RRTYPE: 7,
  EXPECT_RRTYPE_BL: 8,
  EXPECT_RDATA: 9,
  EXPECT_DIR_TTL_BL: 10,
  EXPECT_DIR_TTL: 11,
  EXPECT_DIR_ORIGIN_BL: 12,
  EXPECT_DIR_ORIGIN: 13,
  EXPECT_DIR_INCLUDE_BL: 14,
  EXPECT_DIR_INCLUDE: 15,
  EXPECT_DIR_GENERATE: 16,
  EXPECT_DIR_GENERATE_BL: 17
};

/**
 * Parse Error
 * @extends {Error}
 */

class ParseError extends Error {
  constructor(msg, tok, file, parent) {
    super();

    if (!msg)
      msg = '';

    if (!tok)
      tok = null;

    if (!file)
      file = '';

    if (!parent)
      parent = ParseError;

    let m = '';

    if (file)
      m += `${file}: `;

    m += `bns: ${msg}`;

    if (tok) {
      m += `: ${JSON.stringify(tok.string)}`;
      m += ' at line:';
      m += ` ${tok.line}:${tok.col}.`;
    }

    this.type = 'ParseError';
    this.code = 'EPARSEERROR';
    this.message = m;
    this.tok = tok;
    this.file = file;

    if (Error.captureStackTrace)
      Error.captureStackTrace(this, parent);
  }
}

/**
 * Item
 */

class Item {
  constructor() {
    this.record = null;
    this.comment = '';
    this.error = null;
  }

  static fromRecord(record, comment) {
    const item = new this();
    item.record = record;
    item.comment = comment || '';
    return item;
  }

  static fromString(msg, tok, file) {
    const err = new ParseError(msg, tok, file, this.fromString);
    const item = new this();
    item.error = err;
    return item;
  }

  static fromError(err, tok, file) {
    if (err.type === 'ParseError') {
      if (tok && !err.tok)
        err.tok = tok;
      if (file && !err.file)
        err.file = file;
    }
    const item = new this();
    item.error = err;
    return item;
  }
}

/**
 * TTL State
 */

class TTLState {
  constructor(ttl, directive) {
    this.ttl = ttl || 0;
    this.directive = directive || false;
  }
}

/**
 * Token
 */

class Token {
  constructor(line, col) {
    this.string = '';
    this.error = false;
    this.type = tokens.EOF;
    this.line = line || 0;
    this.col = col || 0;
    this.value = 0;
    this.comment = '';
  }

  end() {
    return this.type === tokens.EOF
        || this.type === tokens.NEWLINE;
  }
}

/*
 * Lexer
 */

function* lexer(input) {
  assert(typeof input === 'string');

  let str = '';
  let com = '';
  let quote = false;
  let escape = false;
  let space = false;
  let commt = false;
  let rrtype = false;
  let owner = true;
  let brace = 0;
  let line = 0;
  let col = 0;

  for (let i = 0; i < input.length; i++) {
    const ch = input[i];

    if (str.length >= MAX_TOKEN) {
      const tok = new Token(line, col);
      tok.string = 'token length insufficient for parsing';
      tok.error = true;
      yield tok;
      return;
    }

    if (com.length >= MAX_TOKEN) {
      const tok = new Token(line, col);
      tok.string = 'comment length insufficient for parsing';
      tok.error = true;
      yield tok;
      return;
    }

    switch (ch) {
      case ' ':
      case '\t': {
        if (escape) {
          escape = false;
          str += ch;
          break;
        }

        if (quote) {
          str += ch;
          break;
        }

        if (commt) {
          com += ch;
          break;
        }

        if (str.length === 0) {
          ;
        } else if (owner) {
          const tok = new Token(line, col);

          tok.type = tokens.OWNER;
          tok.string = str;

          switch (str.toUpperCase()) {
            case '$TTL':
              tok.type = tokens.DIR_TTL;
              break;
            case '$ORIGIN':
              tok.type = tokens.DIR_ORIGIN;
              break;
            case '$INCLUDE':
              tok.type = tokens.DIR_INCLUDE;
              break;
            case '$GENERATE':
              tok.type = tokens.DIR_GENERATE;
              break;
          }

          yield tok;
        } else {
          const upper = str.toUpperCase();
          const tok = new Token(line, col);

          tok.type = tokens.STRING;
          tok.string = str;

          if (!rrtype) {
            let t = types[upper];

            if (t != null) {
              tok.type = tokens.RRTYPE;
              tok.value = t;
              rrtype = true;
            } else {
              if (util.startsWith(upper, 'TYPE')) {
                try {
                  t = stringToType(upper);
                } catch (e) {
                  const tok = new Token(line, col);
                  tok.string = 'unknown RR type';
                  tok.error = true;
                  yield tok;
                  return;
                }
                tok.type = tokens.RRTYPE;
                tok.value = t;
                rrtype = true;
              }
            }

            t = classes[upper];

            if (t != null) {
              tok.type = tokens.CLASS;
              tok.value = t;
            } else {
              if (util.startsWith(upper, 'CLASS')) {
                try {
                  t = stringToClass(upper);
                } catch (e) {
                  const tok = new Token(line, col);
                  tok.string = 'unknown class';
                  tok.error = true;
                  yield tok;
                  return;
                }
                tok.type = tokens.CLASS;
                tok.value = t;
              }
            }
          }

          yield tok;
        }

        str = '';

        if (!space && !commt) {
          const tok = new Token(line, col);
          tok.type = tokens.BLANK;
          tok.string = ' ';
          yield tok;
        }

        owner = false;
        space = true;

        break;
      }

      case ';': {
        if (escape) {
          escape = false;
          str += ch;
          break;
        }

        if (quote) {
          str += ch;
          break;
        }

        if (str.length > 0) {
          const tok = new Token(line, col);

          tok.type = tokens.STRING;
          tok.string = str;

          yield tok;

          str = '';
        }

        commt = true;
        com += ';';

        break;
      }

      case '\r': {
        escape = false;

        if (quote) {
          str += ch;
          break;
        }

        break;
      }

      case '\n': {
        escape = false;
        line += 1;
        col = 0;

        if (quote) {
          str += ch;
          break;
        }

        if (commt) {
          commt = false;
          rrtype = false;
          str = '';

          if (brace === 0) {
            owner = true;

            const tok = new Token(line, col);

            tok.type = tokens.NEWLINE;
            tok.string = '\n';
            tok.comment = com;

            yield tok;

            com = '';

            break;
          }

          com += ' ';

          break;
        }

        if (brace === 0) {
          if (str.length > 0) {
            const tok = new Token(line, col);

            tok.type = tokens.STRING;
            tok.string = str;

            if (!rrtype) {
              const t = types[str.toUpperCase()];
              if (t != null) {
                tok.type = tokens.RRTYPE;
                tok.value = t;
                rrtype = true;
              }
            }

            yield tok;
          }

          const tok = new Token(line, col);

          tok.type = tokens.NEWLINE;
          tok.string = '\n';

          yield tok;

          str = '';
          commt = false;
          rrtype = false;
          owner = true;
          com = '';
        }

        break;
      }

      case '\\': {
        if (commt) {
          com += ch;
          break;
        }

        if (escape) {
          str += ch;
          escape = false;
          break;
        }

        str += ch;
        escape = true;
        break;
      }

      case '"': {
        if (commt) {
          com += ch;
          break;
        }

        if (escape) {
          str += ch;
          escape = false;
          break;
        }

        space = false;

        if (str.length > 0) {
          const tok = new Token(line, col);

          tok.type = tokens.STRING;
          tok.string = str;

          yield tok;

          str = '';
        }

        const tok = new Token(line, col);

        tok.type = tokens.QUOTE;
        tok.string = '"';

        yield tok;

        quote = !quote;

        break;
      }

      case '(':
      case ')': {
        if (commt) {
          com += ch;
          break;
        }

        if (escape) {
          str += ch;
          escape = false;
          break;
        }

        if (quote) {
          str += ch;
          break;
        }

        switch (ch) {
          case '(': {
            brace += 1;
            break;
          }
          case ')': {
            brace -= 1;
            if (brace < 0) {
              const tok = new Token(line, col);
              tok.string = 'extra closing brace';
              tok.error = true;
              yield tok;
              return;
            }
          }
        }

        break;
      }

      default: {
        escape = false;

        if (commt) {
          com += ch;
          break;
        }

        str += ch;
        space = false;

        break;
      }
    }

    col += 1;
  }

  if (str.length > 0) {
    const tok = new Token(line, col);
    tok.string = str;
    tok.type = tokens.STRING;
    tok.comment = com;
    yield tok;
  }

  if (brace !== 0) {
    const tok = new Token(line, col);
    tok.string = 'unbalanced brace';
    tok.error = true;
    yield tok;
    return;
  }

  const tok = new Token(line, col);

  tok.string = '';
  tok.type = tokens.EOF;
  tok.comment = com;

  yield tok;

  return;
}

/*
 * Parser
 */

function* parser(wire, input, origin, file, def, include) {
  if (origin == null)
    origin = '';

  if (file == null)
    file = '';

  if (def == null)
    def = null;

  if (include == null)
    include = 1;

  assert(typeof input === 'string');
  assert(typeof origin === 'string');
  assert(typeof file === 'string');
  assert(def === null || (def instanceof TTLState));
  assert((include >>> 0) === include);

  if (origin !== '') {
    origin = util.fqdn(origin);

    if (!util.isName(origin)) {
      yield Item.fromString('bad initial origin name', new Token(), file);
      return;
    }
  }

  const hdr = new wire.Record();

  let state = states.EXPECT_OWNER_DIR;
  let prev = '';

  const iter = lexer(input);

  for (const tok of iter) {
    if (tok.error) {
      yield Item.fromString(tok.string, tok, file);
      return;
    }

    if (tok.type === tokens.EOF)
      break;

    switch (state) {
      case states.EXPECT_OWNER_DIR: {
        if (def)
          hdr.ttl = def.ttl;

        hdr.class = classes.IN;

        switch (tok.type) {
          case tokens.NEWLINE: {
            state = states.EXPECT_OWNER_DIR;
            break;
          }

          case tokens.OWNER: {
            let name;

            hdr.name = tok.string;

            try {
              name = toAbsoluteName(tok.string, origin);
            } catch (e) {
              yield Item.fromString('bad owner name', tok, file);
              return;
            }

            hdr.name = name;
            prev = name;
            state = states.EXPECT_OWNER_BL;

            break;
          }

          case tokens.DIR_TTL: {
            state = states.EXPECT_DIR_TTL_BL;
            break;
          }

          case tokens.DIR_ORIGIN: {
            state = states.EXPECT_DIR_ORIGIN_BL;
            break;
          }

          case tokens.DIR_INCLUDE: {
            state = states.EXPECT_DIR_INCLUDE_BL;
            break;
          }

          case tokens.DIR_GENERATE: {
            state = states.EXPECT_DIR_GENERATE_BL;
            break;
          }

          case tokens.RRTYPE: {
            hdr.name = prev;
            hdr.type = tok.value;
            state = states.EXPECT_RDATA;
            break;
          }

          case tokens.CLASS: {
            hdr.name = prev;
            hdr.class = tok.value;
            state = states.EXPECT_ANY_NO_CLASS_BL;
            break;
          }

          case tokens.BLANK: {
            break;
          }

          case tokens.STRING: {
            let ttl;

            try {
              ttl = stringToTTL(tok.string);
            } catch (e) {
              yield Item.fromString('not a TTL', tok, file);
              return;
            }

            hdr.ttl = ttl;

            if (!def || !def.directive)
              def = new TTLState(ttl, false);

            state = states.EXPECT_ANY_NO_TTL_BL;

            break;
          }

          default: {
            yield Item.fromString('syntax error at beginning', tok, file);
            return;
          }
        }

        break;
      }

      case states.EXPECT_DIR_INCLUDE_BL: {
        if (tok.type !== tokens.BLANK) {
          yield Item.fromString('no blank after $INCLUDE', tok, file);
          return;
        }
        state = states.EXPECT_DIR_INCLUDE;
        break;
      }

      case states.EXPECT_DIR_INCLUDE: {
        if (tok.type !== tokens.STRING) {
          yield Item.fromString('expected $INCLUDE value', tok, file);
          return;
        }

        if (!file) {
          yield Item.fromString('no path provided for $INCLUDE', tok, file);
          return;
        }

        let path = tok.string;
        let child = origin;

        const next = read(iter);

        switch (next.type) {
          case tokens.BLANK: {
            const next = read(iter);

            if (next.type === tokens.STRING) {
              let name;
              try {
                name = toAbsoluteName(next.string, origin);
              } catch (e) {
                yield Item.fromString('bad origin name', next, file);
                return;
              }
              child = name;
            }

            break;
          }

          case tokens.EOF:
          case tokens.NEWLINE: {
            break;
          }

          default: {
            yield Item.fromString('garbage after $INCLUDE', next, file);
            return;
          }
        }

        const dir = Path.dirname(file);

        path = Path.resolve(dir, path);

        let text;
        try {
          text = fs.readFileSync(path, 'utf8');
        } catch (e) {
          yield Item.fromString(`failed to open ${path}`, tok, file);
          return;
        }

        if (include + 1 > MAX_INCLUDES) {
          yield Item.fromString('too deeply nested $INCLUDE', tok, file);
          return;
        }

        yield parser(wire, text, child, path, def, include + 1);

        state = states.EXPECT_OWNER_DIR;

        break;
      }

      case states.EXPECT_DIR_TTL_BL: {
        if (tok.type !== tokens.BLANK) {
          yield Item.fromString('no blank after $TTL', tok, file);
          return;
        }
        state = states.EXPECT_DIR_TTL;
        break;
      }

      case states.EXPECT_DIR_TTL: {
        if (tok.type !== tokens.STRING) {
          yield Item.fromString('expected $TTL value', tok, file);
          return;
        }

        try {
          slurpRemainder(iter, file);
        } catch (e) {
          yield Item.fromError(e, tok, file);
          return;
        }

        let ttl;
        try {
          ttl = stringToTTL(tok.string);
        } catch (e) {
          yield Item.fromString('expected $TTL value', tok, file);
          return;
        }

        def = new TTLState(ttl, true);
        state = states.EXPECT_OWNER_DIR;

        break;
      }

      case states.EXPECT_DIR_ORIGIN_BL: {
        if (tok.type !== tokens.BLANK) {
          yield Item.fromString('no blank after $ORIGIN', tok, file);
          return;
        }
        state = states.EXPECT_DIR_ORIGIN;
        break;
      }

      case states.EXPECT_DIR_ORIGIN: {
        if (tok.type !== tokens.STRING) {
          yield Item.fromString('expected $ORIGIN value', tok, file);
          return;
        }

        try {
          slurpRemainder(iter, file);
        } catch (e) {
          yield Item.fromError(e, tok, file);
          return;
        }

        let name;
        try {
          name = toAbsoluteName(tok.string, origin);
        } catch (e) {
          yield Item.fromString('bad origin name', tok, file);
          return;
        }

        origin = name;
        state = states.EXPECT_OWNER_DIR;

        break;
      }

      case states.EXPECT_DIR_GENERATE_BL: {
        if (tok.type !== tokens.BLANK) {
          yield Item.fromString('no blank after $GENERATE', tok, file);
          return;
        }
        state = states.EXPECT_DIR_GENERATE;
        break;
      }

      case states.EXPECT_DIR_GENERATE: {
        if (tok.type !== tokens.STRING) {
          yield Item.fromString('expected $GENERATE value', tok, file);
          return;
        }

        try {
          yield generate(iter, tok, origin);
        } catch (e) {
          yield Item.fromError(e, tok, file);
          return;
        }

        state = states.EXPECT_OWNER_DIR;

        break;
      }

      case states.EXPECT_OWNER_BL: {
        if (tok.type !== tokens.BLANK) {
          yield Item.fromString('no blank after owner', tok, file);
          return;
        }
        state = states.EXPECT_ANY;
        break;
      }

      case states.EXPECT_ANY: {
        switch (tok.type) {
          case tokens.RRTYPE: {
            if (!def) {
              yield Item.fromString('missing TTL', tok, file);
              return;
            }
            hdr.type = tok.value;
            state = states.EXPECT_RDATA;
            break;
          }
          case tokens.CLASS: {
            hdr.class = tok.value;
            state = states.EXPECT_ANY_NO_CLASS_BL;
            break;
          }
          case tokens.STRING: {
            let ttl;

            try {
              ttl = stringToTTL(tok.string);
            } catch (e) {
              yield Item.fromString('not a TTL', tok, file);
              return;
            }

            hdr.ttl = ttl;

            if (!def || !def.directive)
              def = new TTLState(ttl, false);

            state = states.EXPECT_ANY_NO_TTL_BL;

            break;
          }
          default: {
            yield Item.fromString('expected RR type, TTL or class', tok, file);
            return;
          }
        }
        break;
      }

      case states.EXPECT_ANY_NO_CLASS_BL: {
        if (tok.type !== tokens.BLANK) {
          yield Item.fromString('no blank before class', tok, file);
          return;
        }
        state = states.EXPECT_ANY_NO_CLASS;
        break;
      }

      case states.EXPECT_ANY_NO_TTL_BL: {
        if (tok.type !== tokens.BLANK) {
          yield Item.fromString('no blank before TTL', tok, file);
          return;
        }
        state = states.EXPECT_ANY_NO_TTL;
        break;
      }

      case states.EXPECT_ANY_NO_TTL: {
        switch (tok.type) {
          case tokens.CLASS: {
            hdr.class = tok.value;
            state = states.EXPECT_RRTYPE_BL;
            break;
          }
          case tokens.RRTYPE: {
            hdr.type = tok.value;
            state = states.EXPECT_RDATA;
            break;
          }
          default: {
            yield Item.fromString('expected RR type or class', tok, file);
            return;
          }
        }
        break;
      }

      case states.EXPECT_ANY_NO_CLASS: {
        switch (tok.type) {
          case tokens.STRING: {
            let ttl;

            try {
              ttl = stringToTTL(tok.string);
            } catch (e) {
              yield Item.fromString('not a TTL', tok, file);
              return;
            }

            hdr.ttl = ttl;

            if (!def || !def.directive)
              def = new TTLState(ttl, false);

            state = states.EXPECT_RRTYPE_BL;

            break;
          }
          case tokens.RRTYPE: {
            hdr.type = tok.value;
            state = states.EXPECT_RDATA;
            break;
          }
          default: {
            yield Item.fromString('expected RR type or TTL', tok, file);
            return;
          }
        }
        break;
      }

      case states.EXPECT_RRTYPE_BL: {
        if (tok.type !== tokens.BLANK) {
          yield Item.fromString('no blank before RR type', tok, file);
          return;
        }
        state = states.EXPECT_RRTYPE;
        break;
      }

      case states.EXPECT_RRTYPE: {
        if (tok.type !== tokens.RRTYPE) {
          yield Item.fromString('unknown RR type', tok, file);
          return;
        }
        hdr.type = tok.value;
        state = states.EXPECT_RDATA;
        break;
      }

      case states.EXPECT_RDATA: {
        let record, comment;

        try {
          [record, comment] = readRecord(wire, iter, hdr, file);
        } catch (e) {
          yield Item.fromError(e, tok, file);
          return;
        }

        yield Item.fromRecord(record, comment);

        state = states.EXPECT_OWNER_DIR;

        break;
      }
    }
  }
}

function* generate(iter, tok, origin) {
  let step = 1;

  const i = tok.string.indexOf('/');

  if (i !== -1) {
    if (i + 1 === tok.string.length)
      throw new ParseError('bad step in $GENERATE range.');

    try {
      step = util.parseU32(tok.string.substring(i + 1));
    } catch (e) {
      throw new ParseError('bad step in $GENERATE range.');
    }

    tok.string = tok.string.substring(0, i);
  }

  const sx = tok.string.split('-', 2);

  if (sx.length !== 2)
    throw new ParseError('bad start-stop in $GENERATE range');

  let start;
  try {
    start = util.parseU32(sx[0]);
  } catch (e) {
    throw new ParseError('bad start in $GENERATE range');
  }

  let end;
  try {
    end = util.parseU32(sx[1]);
  } catch (e) {
    throw new ParseError('bad stop in $GENERATE range');
  }

  if (end < start)
    throw new ParseError('bad range in $GENERATE range');

  read(iter);

  let str = '';

  for (;;) {
    const tok = read(iter);

    if (tok.end())
      break;

    str += tok.string;
  }

  for (let i = 0; i <= end; i += step) {
    let escape = false;
    let dom = '';

    for (let j = 0; j < str.length; j++) {
      const ch = str[j];

      switch (ch) {
        case '\\': {
          if (escape) {
            dom += '\\';
            escape = false;
            continue;
          }
          escape = true;
          break;
        }

        case '$': {
          if (escape) {
            dom += '$';
            escape = false;
            continue;
          }

          escape = false;

          if (j + 1 >= str.length) {
            dom += i.toString(10);
            continue;
          }

          if (str[j + 1] === '$') {
            dom += '$';
            j += 1;
            continue;
          }

          if (str[j + 1] === '{') {
            const sub = str.substring(j + 2);
            const sep = sub.indexOf('}');

            if (sep === -1)
              throw new ParseError('bad modifier in $GENERATE');

            const fmt = str.substring(j + 2, j + 2 + sep);

            j += 2 + sep;
            dom += printf(fmt, i);

            continue;
          }

          dom += i.toString(10);

          break;
        }

        default: {
          if (escape) {
            escape = false;
            continue;
          }

          dom += ch;
          break;
        }
      }

      const rr = parseRecord(`$ORIGIN ${origin}\n${dom}`);

      yield Item.fromRecord(rr, '');
    }
  }
}

function printf(fmt, index) {
  const xs = fmt.split(',', 3);

  if (xs.length !== 3)
    throw new ParseError('bad modifier in $GENERATE');

  const offset = parseInt(xs[0], 10);

  if (!isFinite(offset) || offset < -255 || offset > 255)
    throw new ParseError('bad offset in $GENERATE');

  let width;
  try {
    width = util.parseU8(xs[1]);
  } catch (e) {
    throw new ParseError('bad width in $GENERATE');
  }

  let base;
  switch (xs[2]) {
    case 'o':
      base = 8;
      break;
    case 'd':
      base = 10;
      break;
    case 'x':
    case 'X':
      base = 16;
      break;
    default:
      throw new ParseError('bad base in $GENERATE');
  }

  // Number to print.
  let num = index + offset;

  const neg = num < 0;

  if (neg)
    num = -num;

  // Stringified
  let str = num.toString(base);

  while (str.length < width)
    str = '0' + str;

  if (neg)
    str = '-' + str;

  return str;
}

function readRecord(wire, iter, hdr, file) {
  const parts = [];

  let str = '';
  let end = false;
  let i = 0;
  let tok = read(iter);

  if (tok.type === tokens.BLANK)
    throw new ParseError('unexpected blank', tok, file);

  if (tok.type === tokens.STRING && tok.string === '\\#')
    return readUnknown(wire, iter, hdr, file);

  const RD = wire.recordsByVal[hdr.type];

  if (!RD)
    throw new ParseError('unknown rr type', tok, file);

  const rr = new wire.Record();

  rr.name = hdr.name;
  rr.type = hdr.type;
  rr.class = hdr.class;
  rr.ttl = hdr.ttl;
  rr.data = new RD();

  const items = rr.data.schema();

  if (i < items.length) {
    end = (items[i][1] & 0x80) !== 0;
    i += 1;
  }

  while (!tok.end()) {
    if (end) {
      str += tok.string;
    } else if (tok.type === tokens.BLANK) {
      parts.push(str);
      str = '';
      if (i < items.length) {
        end = (items[i][1] & 0x80) !== 0;
        i += 1;
      }
    } else {
      str += tok.string;
    }

    tok = read(iter);
  }

  if (str.length > 0) {
    parts.push(str);
    str = '';
  }

  if (parts.length !== items.length)
    throw new ParseError('missing items in rd', tok, file);

  for (let i = 0; i < parts.length; i++) {
    const part = parts[i];
    const [name, type] = items[i];

    rr.data[name] = schema.readType(type, part, rr.data);
  }

  return [rr, ''];
}

function readUnknown(wire, iter, hdr, file) {
  const rr = new wire.Record();

  rr.name = hdr.name;
  rr.type = hdr.type;
  rr.class = hdr.class;
  rr.ttl = hdr.ttl;

  let RD = wire.recordsByVal[hdr.type];

  if (!RD)
    RD = wire.UNKNOWNRecord;

  expect(iter, tokens.BLANK);

  const next = expect(iter, tokens.STRING);
  const size = util.parseU32(next.string);

  let hex = '';

  for (;;) {
    const tok = read(iter);

    if (tok.end())
      break;

    switch (tok.type) {
      case tokens.BLANK:
        break;
      case tokens.STRING:
        hex += tok.string;
        break;
      default:
        throw new ParseError('unexpected token', tok, file);
    }
  }

  if (size !== (hex.length >>> 1))
    throw new ParseError('invalid hex size', tok, file);

  const rd = util.parseHex(hex);

  rr.data = RD.decode(rd);

  return [rr, ''];
}

/*
 * API
 */

function parseZone(wire, input, origin, file) {
  const def = new TTLState(DEFAULT_TTL, false);
  const iter = parser(wire, input, origin, file, def, 1);
  const out = [];

  for (const item of iter) {
    if (item.error)
      throw item.error;

    out.push(item.record);
  }

  return out;
}

function parseRecord(wire, str) {
  const def = new TTLState(DEFAULT_TTL, false);
  const iter = parser(wire, str, '', '', def, 1);
  const it = iter.next();

  if (it.done)
    throw new ParseError('no record');

  const item = it.value;

  if (item.error)
    throw item.error;

  return item.record;
}

function parseRD(wire, type, input) {
  assert((type & 0xffff) === type);

  const RD = wire.recordsByVal[type];

  if (!RD)
    throw new ParseError('unknown rr type');

  const parts = [];
  const iter = lexer(input);
  const rd = new RD();
  const items = rd.schema();

  let tok = read(iter);
  let end = false;
  let str = '';
  let i = 0;

  if (i < items.length) {
    end = (items[i][1] & 0x80) !== 0;
    i += 1;
  }

  while (!tok.end()) {
    if (end) {
      str += tok.string;
    } else if (tok.type === tokens.BLANK) {
      parts.push(str);
      str = '';
      if (i < items.length) {
        end = (items[i][1] & 0x80) !== 0;
        i += 1;
      }
    } else {
      str += tok.string;
    }

    tok = read(iter);
  }

  if (str.length > 0) {
    parts.push(str);
    str = '';
  }

  if (parts.length !== items.length)
    throw new ParseError('missing items in rd', tok);

  for (let i = 0; i < parts.length; i++) {
    const part = parts[i];
    const [name, type] = items[i];

    rd[name] = schema.readType(type, part, rd);
  }

  return rd;
}

/*
 * Helpers
 */

function read(iter) {
  const it = iter.next();

  if (it.done) {
    const tok = new Token();
    tok.type = tokens.EOF;
    return tok;
  }

  return it.value;
}

function expect(iter, type) {
  const tok = read(iter);

  if (tok.type !== type)
    throw new ParseError('unexpected token', tok);

  return tok;
}

function slurpRemainder(iter, file) {
  const tok = read(iter);

  switch (tok.type) {
    case tokens.BLANK: {
      const tok = read(iter);

      if (tok.type !== tokens.NEWLINE && tok.type !== tokens.EOF)
        throw new ParseError('garbage after rdata', tok, file);

      return tok.comment;
    }

    case tokens.NEWLINE: {
      return tok.comment;
    }

    default: {
      throw new ParseError('garbage after rdata', tok, file);
    }
  }
}

function stringToTTL(str) {
  assert(typeof str === 'string');

  let s = 0;
  let w = 0;

  if (str.length === 0 || str.length > 20)
    throw new Error('Invalid TTL.');

  for (let i = 0; i < str.length; i++) {
    const ch = str[i];

    switch (ch) {
      case 's':
      case 'S':
        s += w;
        w = 0;
        break;
      case 'm':
      case 'M':
        s += w * 60;
        w = 0;
        break;
      case 'h':
      case 'H':
        s += w * 60 * 60;
        w = 0;
        break;
      case 'd':
      case 'D':
        s += w * 60 * 60 * 24;
        w = 0;
        break;
      case 'w':
      case 'W':
        s += w * 60 * 60 * 24 * 7;
        w = 0;
        break;
      case '0':
      case '1':
      case '2':
      case '3':
      case '4':
      case '5':
      case '6':
      case '7':
      case '8':
      case '9':
        w *= 10;
        w += str.charCodeAt(i) - 0x30;
        break;
      default:
        throw new Error('Invalid TTL.');
    }
  }

  return s + w;
}

function toAbsoluteName(name, origin) {
  assert(typeof name === 'string');
  assert(typeof origin === 'string');

  if (name === '@') {
    if (origin === '')
      throw new Error('Bad origin.');

    return origin;
  }

  if (!util.isName(name) || name === '')
    throw new Error('Bad name.');

  if (util.isFQDN(name))
    return name;

  if (origin === '')
    throw new Error('Bad origin.');

  return appendOrigin(name, origin);
}

function appendOrigin(name, origin) {
  assert(typeof name === 'string');
  assert(typeof origin === 'string');

  if (origin === '.')
    return name + origin;

  return name + '.' + origin;
}
