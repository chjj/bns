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
const {Record} = wire;

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
const DEFAULT_TTL = 3600;

const states = {
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
  KEY: 13,
  EXPECT_OWNER_DIR: 14,
  EXPECT_OWNER_BL: 15,
  EXPECT_ANY: 16,
  EXPECT_ANY_NO_CLASS: 17,
  EXPECT_ANY_NO_CLASS_BL: 18,
  EXPECT_ANY_NO_TTL: 19,
  EXPECT_ANY_NO_TTL_BL: 20,
  EXPECT_RRTYPE: 21,
  EXPECT_RRTYPE_BL: 22,
  EXPECT_RDATA: 23,
  EXPECT_DIR_TTL_BL: 24,
  EXPECT_DIR_TTL: 25,
  EXPECT_DIR_ORIGIN_BL: 26,
  EXPECT_DIR_ORIGIN: 27,
  EXPECT_DIR_INCLUDE_BL: 28,
  EXPECT_DIR_INCLUDE: 29,
  EXPECT_DIR_GENERATE: 30,
  EXPECT_DIR_GENERATE_BL: 31
};

/**
 * Parse Error
 * @extends {Error}
 */

class ParseError extends Error {
  constructor(msg, lex, file, parent) {
    super();

    if (!msg)
      msg = '';

    if (!lex)
      lex = null;

    if (!file)
      file = '';

    if (!parent)
      parent = ParseError;

    let m = '';

    if (file)
      m += `${file}: `;

    m += `bns: ${msg}`;

    if (lex) {
      m += `: ${JSON.stringify(lex.string)}`;
      m += ' at line:';
      m += ` ${lex.line}:${lex.col}.`;
    }

    this.type = 'ParseError';
    this.code = 'EPARSEERROR';
    this.message = m;
    this.lex = lex;
    this.file = file;

    if (Error.captureStackTrace)
      Error.captureStackTrace(this, parent);
  }
}

/**
 * Token
 */

class Token {
  constructor() {
    this.record = null;
    this.comment = '';
    this.error = null;
  }

  static fromRecord(record, comment) {
    const tok = new this();
    tok.record = record;
    tok.comment = comment || '';
    return tok;
  }

  static fromString(msg, lex, file) {
    const err = new ParseError(msg, lex, file, this.fromString);
    const tok = new this();
    tok.error = err;
    return tok;
  }

  static fromError(err, lex, file) {
    if (err.type === 'ParseError') {
      if (lex && !err.lex)
        err.lex = lex;
      if (file && !err.file)
        err.file = file;
    }
    const tok = new this();
    tok.error = err;
    return tok;
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
 * Lex
 */

class Lex {
  constructor(line, col) {
    this.string = '';
    this.error = false;
    this.type = states.EOF;
    this.line = line || 0;
    this.col = col || 0;
    this.value = 0;
    this.comment = '';
  }

  end() {
    return this.type === states.EOF
        || this.type === states.NEWLINE;
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
      const lex = new Lex(line, col);
      lex.string = 'token length insufficient for parsing';
      lex.error = true;
      yield lex;
      return;
    }

    if (com.length >= MAX_TOKEN) {
      const lex = new Lex(line, col);
      lex.string = 'comment length insufficient for parsing';
      lex.error = true;
      yield lex;
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
          const lex = new Lex(line, col);

          lex.type = states.OWNER;
          lex.string = str;

          switch (str.toUpperCase()) {
            case '$TTL':
              lex.type = states.DIR_TTL;
              break;
            case '$ORIGIN':
              lex.type = states.DIR_ORIGIN;
              break;
            case '$INCLUDE':
              lex.type = states.DIR_INCLUDE;
              break;
            case '$GENERATE':
              lex.type = states.DIR_GENERATE;
              break;
          }

          yield lex;
        } else {
          const upper = str.toUpperCase();
          const lex = new Lex(line, col);

          lex.type = states.STRING;
          lex.string = str;

          if (!rrtype) {
            let t = types[upper];

            if (t != null) {
              lex.type = states.RRTYPE;
              lex.value = t;
              rrtype = true;
            } else {
              if (util.startsWith(upper, 'TYPE')) {
                try {
                  t = stringToType(upper);
                } catch (e) {
                  const lex = new Lex(line, col);
                  lex.string = 'unknown RR type';
                  lex.error = true;
                  yield lex;
                  return;
                }
                lex.type = states.RRTYPE;
                lex.value = t;
                rrtype = true;
              }
            }

            t = classes[upper];

            if (t != null) {
              lex.type = states.CLASS;
              lex.value = t;
            } else {
              if (util.startsWith(upper, 'CLASS')) {
                try {
                  t = stringToClass(upper);
                } catch (e) {
                  const lex = new Lex(line, col);
                  lex.string = 'unknown class';
                  lex.error = true;
                  yield lex;
                  return;
                }
                lex.type = states.CLASS;
                lex.value = t;
              }
            }
          }

          yield lex;
        }

        str = '';

        if (!space && !commt) {
          const lex = new Lex(line, col);
          lex.type = states.BLANK;
          lex.string = ' ';
          yield lex;
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
          const lex = new Lex(line, col);

          lex.type = states.STRING;
          lex.string = str;

          yield lex;

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

            const lex = new Lex(line, col);

            lex.type = states.NEWLINE;
            lex.string = '\n';
            lex.comment = com;

            yield lex;

            com = '';

            break;
          }

          com += ' ';

          break;
        }

        if (brace === 0) {
          if (str.length > 0) {
            const lex = new Lex(line, col);

            lex.type = states.STRING;
            lex.string = str;

            if (!rrtype) {
              const t = types[str.toUpperCase()];
              if (t != null) {
                lex.type = states.RRTYPE;
                lex.value = t;
                rrtype = true;
              }
            }

            yield lex;
          }

          const lex = new Lex(line, col);

          lex.type = states.NEWLINE;
          lex.string = '\n';

          yield lex;

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
          const lex = new Lex(line, col);

          lex.type = states.STRING;
          lex.string = str;

          yield lex;

          str = '';
        }

        const lex = new Lex(line, col);

        lex.type = states.QUOTE;
        lex.string = '"';

        yield lex;

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
              const lex = new Lex(line, col);
              lex.string = 'extra closing brace';
              lex.error = true;
              yield lex;
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
    const lex = new Lex(line, col);
    lex.string = str;
    lex.type = states.STRING;
    lex.comment = com;
    yield lex;
  }

  if (brace !== 0) {
    const lex = new Lex(line, col);
    lex.string = 'unbalanced brace';
    lex.error = true;
    yield lex;
    return;
  }

  const lex = new Lex(line, col);

  lex.string = '';
  lex.type = states.EOF;
  lex.comment = com;

  yield lex;

  return;
}

/*
 * Parser
 */

function* parser(input, origin, file, def, include) {
  if (origin == null)
    origin = '';

  if (file == null)
    file = '';

  if (include == null)
    include = 1;

  assert(typeof input === 'string');
  assert(typeof origin === 'string');
  assert(typeof file === 'string');
  assert(def == null || (def instanceof TTLState));
  assert((include >>> 0) === include);

  if (origin !== '') {
    origin = util.fqdn(origin);

    if (!util.isName(origin)) {
      yield Token.fromString('bad initial origin name', new Lex(), file);
      return;
    }
  }

  const hdr = new Record();

  let state = states.EXPECT_OWNER_DIR;
  let prev = '';

  const iter = lexer(input);

  for (let lex of iter) {
    if (lex.error) {
      yield Token.fromString(lex.string, lex, file);
      return;
    }

    if (lex.type === states.EOF)
      break;

    switch (state) {
      case states.EXPECT_OWNER_DIR: {
        if (def)
          hdr.ttl = def.ttl;

        hdr.class = classes.IN;

        switch (lex.type) {
          case states.NEWLINE: {
            state = states.EXPECT_OWNER_DIR;
            break;
          }

          case states.OWNER: {
            let name;

            hdr.name = lex.string;

            try {
              name = toAbsoluteName(lex.string, origin);
            } catch (e) {
              yield Token.fromString('bad owner name', lex, file);
              return;
            }

            hdr.name = name;
            prev = name;
            state = states.EXPECT_OWNER_BL;

            break;
          }

          case states.DIR_TTL: {
            state = states.EXPECT_DIR_TTL_BL;
            break;
          }

          case states.DIR_ORIGIN: {
            state = states.EXPECT_DIR_ORIGIN_BL;
            break;
          }

          case states.DIR_INCLUDE: {
            state = states.EXPECT_DIR_INCLUDE_BL;
            break;
          }

          case states.DIR_GENERATE: {
            state = states.EXPECT_DIR_GENERATE_BL;
            break;
          }

          case states.RRTYPE: {
            hdr.name = prev;
            hdr.type = lex.value;
            state = states.EXPECT_RDATA;
            break;
          }

          case states.CLASS: {
            hdr.name = prev;
            hdr.class = lex.value;
            state = states.EXPECT_ANY_NO_CLASS_BL;
            break;
          }

          case states.BLANK: {
            break;
          }

          case states.STRING: {
            let ttl;

            try {
              ttl = stringToTTL(lex.string);
            } catch (e) {
              yield Token.fromString('not a TTL', lex, file);
              return;
            }

            hdr.ttl = ttl;

            if (!def || !def.directive)
              def = new TTLState(ttl, false);

            state = states.EXPECT_ANY_NO_TTL_BL;

            break;
          }

          default: {
            yield Token.fromString('syntax error at beginning', lex, file);
            return;
          }
        }

        break;
      }

      case states.EXPECT_DIR_INCLUDE_BL: {
        if (lex.type !== states.BLANK) {
          yield Token.fromString('no blank after $INCLUDE-directive', lex, file);
          return;
        }
        state = states.EXPECT_DIR_INCLUDE;
        break;
      }

      case states.EXPECT_DIR_INCLUDE: {
        if (lex.type !== states.STRING) {
          yield Token.fromString('expected $INCLUDE value', lex, file);
          return;
        }

        if (!file) {
          yield Token.fromString('no path provided for $INCLUDE', lex, file);
          return;
        }

        let path = lex.string;
        let dir = null;
        let child = origin;
        let text;

        const n = read(iter);

        switch (n.type) {
          case states.BLANK: {
            const n = read(iter);

            if (n.type === states.STRING) {
              let name;
              try {
                name = toAbsoluteName(n.string, origin);
              } catch (e) {
                yield Token.fromString('bad origin name', n, file);
                return;
              }
              child = name;
            }

            break;
          }

          case states.EOF:
          case states.NEWLINE: {
            break;
          }

          default: {
            yield Token.fromString('garbage after $INCLUDE', n, file);
            return;
          }
        }

        dir = Path.dirname(file);
        path = Path.resolve(dir, path);

        try {
          text = fs.readFileSync(path, 'utf8');
        } catch (e) {
          yield Token.fromString(`failed to open ${path}`, lex, file);
          return;
        }

        if (include + 1 > 7) {
          yield Token.fromString('too deeply nested $INCLUDE', lex, file);
          return;
        }

        yield parser(text, child, path, def, include + 1);

        state = states.EXPECT_OWNER_DIR;

        break;
      }

      case states.EXPECT_DIR_TTL_BL: {
        if (lex.type !== states.BLANK) {
          yield Token.fromString('no blank after $TTL-directive', lex, file);
          return;
        }
        state = states.EXPECT_DIR_TTL;
        break;
      }

      case states.EXPECT_DIR_TTL: {
        if (lex.type !== states.STRING) {
          yield Token.fromString('expected $TTL value', lex, file);
          return;
        }

        try {
          slurpRemainder(iter, file);
        } catch (e) {
          yield Token.fromError(e, lex, file);
          return;
        }

        let ttl;
        try {
          ttl = stringToTTL(lex.string);
        } catch (e) {
          yield Token.fromString('expected $TTL value', lex, file);
          return;
        }

        def = new TTLState(ttl, true);
        state = states.EXPECT_OWNER_DIR;

        break;
      }

      case states.EXPECT_DIR_ORIGIN_BL: {
        if (lex.type !== states.BLANK) {
          yield Token.fromString('no blank after $ORIGIN-directive', lex, file);
          return;
        }
        state = states.EXPECT_DIR_ORIGIN;
        break;
      }

      case states.EXPECT_DIR_ORIGIN: {
        if (lex.type !== states.STRING) {
          yield Token.fromString('expected $ORIGIN value', lex, file);
          return;
        }

        try {
          slurpRemainder(iter, file);
        } catch (e) {
          yield Token.fromError(e, lex, file);
          return;
        }

        let name;
        try {
          name = toAbsoluteName(lex.string, origin);
        } catch (e) {
          yield Token.fromString('bad origin name', lex, file);
          return;
        }

        origin = name;
        state = states.EXPECT_OWNER_DIR;

        break;
      }

      case states.EXPECT_DIR_GENERATE_BL: {
        if (lex.type !== states.BLANK) {
          yield Token.fromString('no blank after $GENERATE-directive', lex, file);
          return;
        }
        state = states.EXPECT_DIR_GENERATE;
        break;
      }

      case states.EXPECT_DIR_GENERATE: {
        if (lex.type !== states.STRING) {
          yield Token.fromString('expected $GENERATE value', lex, file);
          return;
        }

        try {
          yield generate(iter, lex, origin);
        } catch (e) {
          yield Token.fromError(e, lex, file);
          return;
        }

        state = states.EXPECT_OWNER_DIR;

        break;
      }

      case states.EXPECT_OWNER_BL: {
        if (lex.type !== states.BLANK) {
          yield Token.fromString('no blank after owner', lex, file);
          return;
        }
        state = states.EXPECT_ANY;
        break;
      }

      case states.EXPECT_ANY: {
        switch (lex.type) {
          case states.RRTYPE: {
            if (!def) {
              yield Token.fromString('missing TTL', lex, file);
              return;
            }
            hdr.type = lex.value;
            state = states.EXPECT_RDATA;
            break;
          }
          case states.CLASS: {
            hdr.class = lex.value;
            state = states.EXPECT_ANY_NO_CLASS_BL;
            break;
          }
          case states.STRING: {
            let ttl;

            try {
              ttl = stringToTTL(lex.string);
            } catch (e) {
              yield Token.fromString('not a TTL', lex, file);
              return;
            }

            hdr.ttl = ttl;

            if (!def || !def.directive)
              def = new TTLState(ttl, false);

            state = states.EXPECT_ANY_NO_TTL_BL;

            break;
          }
          default: {
            yield Token.fromString('expected RR type, TTL or class', lex, file);
            return;
          }
        }
        break;
      }

      case states.EXPECT_ANY_NO_CLASS_BL: {
        if (lex.type !== states.BLANK) {
          yield Token.fromString('no blank before class', lex, file);
          return;
        }
        state = states.EXPECT_ANY_NO_CLASS;
        break;
      }

      case states.EXPECT_ANY_NO_TTL_BL: {
        if (lex.type !== states.BLANK) {
          yield Token.fromString('no blank before TTL', lex, file);
          return;
        }
        state = states.EXPECT_ANY_NO_TTL;
        break;
      }

      case states.EXPECT_ANY_NO_TTL: {
        switch (lex.type) {
          case states.CLASS: {
            hdr.class = lex.value;
            state = states.EXPECT_RRTYPE_BL;
            break;
          }
          case states.RRTYPE: {
            hdr.type = lex.value;
            state = states.EXPECT_RDATA;
            break;
          }
          default: {
            yield Token.fromString('expected RR type or class', lex, file);
            return;
          }
        }
        break;
      }

      case states.EXPECT_ANY_NO_CLASS: {
        switch (lex.type) {
          case states.STRING: {
            let ttl;

            try {
              ttl = stringToTTL(lex.string);
            } catch (e) {
              yield Token.fromString('not a TTL', lex, file);
              return;
            }

            hdr.ttl = ttl;

            if (!def || !def.directive)
              def = new TTLState(ttl, false);

            state = states.EXPECT_RRTYPE_BL;

            break;
          }
          case states.RRTYPE: {
            hdr.type = lex.value;
            state = states.EXPECT_RDATA;
            break;
          }
          default: {
            yield Token.fromString('expected RR type or TTL', lex, file);
            return;
          }
        }
        break;
      }

      case states.EXPECT_RRTYPE_BL: {
        if (lex.type !== states.BLANK) {
          yield Token.fromString('no blank before RR type', lex, file);
          return;
        }
        state = states.EXPECT_RRTYPE;
        break;
      }

      case states.EXPECT_RRTYPE: {
        if (lex.type !== states.RRTYPE) {
          yield Token.fromString('unknown RR type', lex, file);
          return;
        }
        hdr.type = lex.value;
        state = states.EXPECT_RDATA;
        break;
      }

      case states.EXPECT_RDATA: {
        let record, comment;

        try {
          [record, comment] = readRecord(iter, hdr, file);
        } catch (e) {
          yield Token.fromError(e, lex, file);
          return;
        }

        yield Token.fromRecord(record, comment);

        state = states.EXPECT_OWNER_DIR;

        break;
      }
    }
  }
}

function* generate(iter, lex, origin) {
  let step = 1;

  const i = lex.string.indexOf('/');

  if (i !== -1) {
    if (i + 1 === lex.string.length)
      throw new ParseError('bad step in $GENERATE range.');

    try {
      step = util.parseU32(lex.string.substring(i + 1));
    } catch (e) {
      throw new ParseError('bad step in $GENERATE range.');
    }

    lex.string = lex.string.substring(0, i);
  }

  const sx = lex.string.split('-', 2);

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
    const lex = read(iter);

    if (lex.end())
      break;

    str += lex.string;
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

      yield Token.fromRecord(rr, '');
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

function readRecord(iter, hdr, file) {
  const parts = [];

  let str = '';
  let end = false;
  let i = 0;
  let lex = read(iter);

  if (lex.type === states.BLANK)
    throw new ParseError('unexpected blank', lex, file);

  if (lex.type === states.STRING && lex.string === '\\#')
    return readUnknown(iter, hdr, file);

  const RD = wire.recordsByVal[hdr.type];

  if (!RD)
    throw new ParseError('unknown rr type', lex, file);

  const rr = new Record();

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

  while (!lex.end()) {
    if (end) {
      str += lex.string;
    } else if (lex.type === states.BLANK) {
      parts.push(str);
      str = '';
      if (i < items.length) {
        end = (items[i][1] & 0x80) !== 0;
        i += 1;
      }
    } else {
      str += lex.string;
    }

    lex = read(iter);
  }

  if (str.length > 0) {
    parts.push(str);
    str = '';
  }

  if (parts.length !== items.length)
    throw new ParseError('missing items in rd', lex, file);

  for (let i = 0; i < parts.length; i++) {
    const part = parts[i];
    const [name, type] = items[i];

    rr.data[name] = schema.readType(type, part, rr.data);
  }

  return [rr, ''];
}

function readUnknown(iter, hdr, file) {
  const rr = new Record();

  rr.name = hdr.name;
  rr.type = hdr.type;
  rr.class = hdr.class;
  rr.ttl = hdr.ttl;

  let RD = wire.recordsByVal[hdr.type];

  if (!RD)
    RD = wire.UNKNOWNRecord;

  expect(iter, states.BLANK);

  const n = expect(iter, states.STRING);
  const size = util.parseU32(n.string);

  let hex = '';

  for (;;) {
    const lex = read(iter);

    if (lex.end())
      break;

    switch (lex.type) {
      case states.BLANK:
        break;
      case states.STRING:
        hex += lex.string;
        break;
      default:
        throw new ParseError('unexpected token', lex, file);
    }
  }

  if (size !== (hex.length >>> 1))
    throw new ParseError('invalid hex size', lex, file);

  const rd = util.parseHex(hex);

  rr.data = RD.decode(rd);

  return [rr, ''];
}

/*
 * API
 */

function parseZone(input, origin, file, ttl) {
  const def = new TTLState(ttl || DEFAULT_TTL, false);
  const out = [];
  const iter = parser(input, origin, file, def, 1);

  for (const tok of iter) {
    if (tok.error)
      throw tok.error;

    out.push(tok.record);
  }

  return out;
}

function parseRecord(str) {
  const ttl = new TTLState(DEFAULT_TTL, false);
  const iter = parser(str, '.', null, ttl, 1);
  const item = iter.next();

  if (item.done)
    throw new ParseError('No record.');

  const tok = item.value;

  if (tok.error)
    throw tok.error;

  return tok.record;
}

/*
 * Helpers
 */

function read(iter) {
  const item = iter.next();

  if (item.done) {
    const lex = new Lex();
    lex.type = states.EOF;
    return lex;
  }

  return item.value;
}

function expect(iter, type) {
  const lex = read(iter);

  if (lex.type !== type)
    throw new ParseError('Unexpected token.', lex);

  return lex;
}

function slurpRemainder(iter, file) {
  const lex = read(iter);

  switch (lex.type) {
    case states.BLANK: {
      const lex = read(iter);

      if (lex.type !== states.NEWLINE && lex.type !== states.EOF)
        throw new ParseError('garbage after rdata', lex, file);

      return lex.comment;
    }

    case states.NEWLINE: {
      return lex.comment;
    }

    default: {
      throw new ParseError('garbage after rdata', lex, file);
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
