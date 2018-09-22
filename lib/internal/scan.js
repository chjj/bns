/*!
 * scan.js - zone file parsing for bns
 * Copyright (c) 2018, Christopher Jeffrey (MIT License).
 * https://github.com/chjj/bns
 *
 * Parts of this software are based on miekg/dns:
 *   https://github.com/miekg/dns/blob/master/scan.go
 *   https://github.com/miekg/dns/blob/master/scan_rr.go
 *   https://github.com/miekg/dns/blob/master/generate.go
 */

/* eslint spaced-comment: 0 */

'use strict';

const assert = require('bsert');
const fs = require('bfile');
const IP = require('binet');
const bio = require('bufio');
const base32 = require('bs32');
const Path = require('path');
const encoding = require('../encoding');
const constants = require('../constants');
const lazy = require('./lazy');
const schema = require('./schema');
const util = require('../util');

const {
  dirname,
  resolve
} = Path;

const {
  types,
  classes,
  options,
  optionToString,
  stringToClass,
  stringToOption,
  stringToType,
  typeToString,
  DEFAULT_TTL,
  LOC_EQUATOR,
  LOC_PRIMEMERIDIAN
} = constants;

/*
 * Constants
 */

const MAX_TOKEN = 2048;
const MAX_INCLUDES = 7;
const DUMMY = Buffer.alloc(0);

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

const tokensByVal = {
  [tokens.EOF]: 'EOF',
  [tokens.STRING]: 'STRING',
  [tokens.BLANK]: 'BLANK',
  [tokens.QUOTE]: 'QUOTE',
  [tokens.NEWLINE]: 'NEWLINE',
  [tokens.RRTYPE]: 'RRTYPE',
  [tokens.OWNER]: 'OWNER',
  [tokens.CLASS]: 'CLASS',
  [tokens.DIR_ORIGIN]: 'DIR_ORIGIN',
  [tokens.DIR_TTL]: 'DIR_TTL',
  [tokens.DIR_INCLUDE]: 'DIR_INCLUDE',
  [tokens.DIR_GENERATE]: 'DIR_GENERATE',
  [tokens.KEY]: 'KEY',
  [tokens.VALUE]: 'VALUE'
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
      msg = 'parse error';

    if (!tok)
      tok = null;

    if (!file)
      file = '';

    if (!parent)
      parent = ParseError;

    if (tok) {
      if (!tok.error) {
        const name = tokensByVal[tok.type] || '';
        msg += `: ${JSON.stringify(tok.string)}`;
        msg += ` (${name.toLowerCase()})`;
      }
      msg += ' at line:';
      msg += ` ${tok.line}:${tok.col}`;
    }

    if (file)
      msg += ` (${file})`;

    msg += '.';

    this.type = 'ParseError';
    this.name = 'ParseError';
    this.code = 'EPARSEERROR';
    this.message = msg;
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
    this.unknown = false;
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

function* lexer(input, zone) {
  if (zone == null)
    zone = true;

  assert(typeof input === 'string');
  assert(typeof zone === 'boolean');

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
        } else if (owner && zone) {
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
          const tok = new Token(line, col);

          tok.type = tokens.STRING;
          tok.string = str;

          if (!rrtype) {
            const upper = str.toUpperCase();
            const t = types[upper];

            if ((t & 0xffff) === t && t !== types.ANY) {
              tok.type = tokens.RRTYPE;
              tok.value = t;
              rrtype = true;
            } else {
              if (util.startsWith(upper, 'TYPE')) {
                let t;
                try {
                  t = stringToType(upper);
                } catch (e) {
                  tok.string = 'unknown RR type';
                  tok.error = true;
                  yield tok;
                  return;
                }
                tok.type = tokens.RRTYPE;
                tok.unknown = true;
                tok.value = t;
                rrtype = true;
              }
            }

            if (!rrtype) {
              const c = classes[upper];

              if ((c & 0xffff) === c) {
                tok.type = tokens.CLASS;
                tok.value = c;
              } else {
                if (util.startsWith(upper, 'CLASS')) {
                  let c;
                  try {
                    c = stringToClass(upper);
                  } catch (e) {
                    tok.string = 'unknown class';
                    tok.error = true;
                    yield tok;
                    return;
                  }
                  tok.type = tokens.CLASS;
                  tok.unknown = true;
                  tok.value = c;
                }
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
              const upper = str.toUpperCase();
              const t = types[upper];

              if ((t & 0xffff) === t && t !== types.ANY) {
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

  assert(wire && typeof wire.fromZone === 'function');
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
  const dir = dirname(file);

  let state = states.EXPECT_OWNER_DIR;
  let unknown = false;
  let prev = '.';

  const iter = lexer(input, true);

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
            try {
              prev = normalize(tok.string, origin);
            } catch (e) {
              yield Item.fromString('bad owner name', tok, file);
              return;
            }

            hdr.name = prev;
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
            unknown = tok.unknown;
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
            try {
              hdr.ttl = stringToTTL(tok.string);
            } catch (e) {
              yield Item.fromString('not a TTL', tok, file);
              return;
            }

            if (!def || !def.directive)
              def = new TTLState(hdr.ttl, false);

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

        let cinput = '';
        let corigin = origin;
        let cfile = tok.string;
        let next;

        try {
          next = read(iter, file);
        } catch (e) {
          yield Item.fromError(e, tok, file);
          return;
        }

        switch (next.type) {
          case tokens.BLANK: {
            try {
              next = read(iter, file);
            } catch (e) {
              yield Item.fromError(e, next, file);
              return;
            }

            if (next.type === tokens.STRING) {
              try {
                corigin = normalize(next.string, origin);
              } catch (e) {
                yield Item.fromString('bad origin name', next, file);
                return;
              }
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

        cfile = resolve(dir, cfile);

        try {
          cinput = fs.readFileSync(cfile, 'utf8');
        } catch (e) {
          yield Item.fromString(`failed to open ${cfile}`, tok, file);
          return;
        }

        if (include + 1 > MAX_INCLUDES) {
          yield Item.fromString('too deeply nested $INCLUDE', tok, file);
          return;
        }

        yield* parser(wire, cinput, corigin, cfile, def, include + 1);

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
          slurp(iter, file);
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
          slurp(iter, file);
        } catch (e) {
          yield Item.fromError(e, tok, file);
          return;
        }

        try {
          origin = normalize(tok.string, origin);
        } catch (e) {
          yield Item.fromString('bad origin name', tok, file);
          return;
        }

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
          yield* generate(wire, iter, tok, origin, file);
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
            unknown = tok.unknown;
            state = states.EXPECT_RDATA;
            break;
          }
          case tokens.CLASS: {
            hdr.class = tok.value;
            state = states.EXPECT_ANY_NO_CLASS_BL;
            break;
          }
          case tokens.STRING: {
            try {
              hdr.ttl = stringToTTL(tok.string);
            } catch (e) {
              yield Item.fromString('not a TTL', tok, file);
              return;
            }

            if (!def || !def.directive)
              def = new TTLState(hdr.ttl, false);

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
            unknown = tok.unknown;
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
            try {
              hdr.ttl = stringToTTL(tok.string);
            } catch (e) {
              yield Item.fromString('not a TTL', tok, file);
              return;
            }

            if (!def || !def.directive)
              def = new TTLState(hdr.ttl, false);

            state = states.EXPECT_RRTYPE_BL;

            break;
          }
          case tokens.RRTYPE: {
            hdr.type = tok.value;
            unknown = tok.unknown;
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
        unknown = tok.unknown;
        state = states.EXPECT_RDATA;
        break;
      }

      case states.EXPECT_RDATA: {
        const parse = unknown ? readUnknown : readRecord;

        let record, comment;
        try {
          [record, comment] = parse(wire, iter, hdr, origin, file);
        } catch (e) {
          yield Item.fromError(e, tok, file);
          return;
        }

        yield Item.fromRecord(record, comment);

        unknown = false;
        state = states.EXPECT_OWNER_DIR;

        break;
      }
    }
  }
}

function* generate(wire, iter, tok, origin, file) {
  let step = 1;

  const i = tok.string.indexOf('/');

  if (i !== -1) {
    if (i + 1 === tok.string.length)
      throw new ParseError('bad step in $GENERATE range.');

    try {
      const sub = tok.string.substring(i + 1);
      step = util.parseU32(sub);
    } catch (e) {
      throw new ParseError('bad step in $GENERATE range.');
    }

    tok.string = tok.string.substring(0, i);
  }

  const sx = tok.string.split('-', 3);

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

  expect(iter, tokens.BLANK, file);

  let str = '';

  for (;;) {
    const tok = read(iter, file);

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
    }

    const rr = parseRecord(wire, `$ORIGIN ${origin}\n${dom}`);

    yield Item.fromRecord(rr, '');
  }
}

function printf(fmt, index) {
  const xs = fmt.split(',', 4);

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

  // Stringified.
  let str = num.toString(base);

  while (str.length < width)
    str = '0' + str;

  if (neg)
    str = '-' + str;

  return str;
}

function readRecord(wire, iter, hdr, origin, file) {
  const RD = wire.recordsByVal[hdr.type];
  const format = schema.records[hdr.type];

  if (!RD)
    throw new ParseError('unknown rr type', null, file);

  const rr = new wire.Record();
  const rd = new RD();

  rr.name = hdr.name;
  rr.type = hdr.type;
  rr.class = hdr.class;
  rr.ttl = hdr.ttl;
  rr.data = rd;

  // Special case.
  if (hdr.type === types.LOC) {
    const comment = parseLOC(rd, iter, file);
    return [rr, comment];
  }

  let field, comment;

  for (const [name, type] of format) {
    [field, comment] = readString(wire, rd, type, iter, origin, file);
    rd[name] = field;
  }

  return [rr, comment];
}

function readUnknown(wire, iter, hdr, origin, file) {
  let RD = wire.recordsByVal[hdr.type];

  if (!RD)
    RD = wire.UNKNOWNRecord;

  const rr = new wire.Record();
  const rd = new RD();

  rr.name = hdr.name;
  rr.type = hdr.type;
  rr.class = hdr.class;
  rr.ttl = hdr.ttl;
  rr.data = rd;

  const tok1 = expect(iter, tokens.STRING, file);

  if (tok1.string !== '\\#')
    throw new ParseError('bad rfc3597 serialization', tok1, file);

  expect(iter, tokens.BLANK, file);

  const tok2 = expect(iter, tokens.STRING, file);

  let size;
  try {
    size = util.parseU32(tok2.string);
  } catch (e) {
    throw new ParseError('bad rfc3597 serialization', tok2, file);
  }

  const [hex, tok3] = concat(iter, file);

  if (size !== (hex.length >>> 1))
    throw new ParseError('invalid rfc3597 size', tok2, file);

  let data;
  try {
    data = util.parseHex(hex);
  } catch (e) {
    throw new ParseError('invalid rfc3597 hex', tok3, file);
  }

  rd.decode(data);

  return [rr, tok3.comment];
}

function readOption(wire, iter, code) {
  const OD = wire.optsByVal[code];
  const format = schema.options[code];

  if (!OD)
    throw new ParseError('unknown option code');

  const op = new wire.Option();
  const od = new OD();

  op.code = code;
  op.option = od;

  let field, comment;

  for (const [name, type] of format) {
    [field, comment] = readString(wire, od, type, iter, '', '');
    od[name] = field;
  }

  return [op, comment];
}

function readUnknownOption(wire, iter, code) {
  let OD = wire.optsByVal[code];

  if (!OD)
    OD = wire.UNKNOWNOption;

  const op = new wire.Option();
  const od = new OD();

  op.code = code;
  op.option = od;

  const tok1 = expect(iter, tokens.STRING, '');

  if (tok1.string !== '\\#')
    throw new ParseError('bad rfc3597 serialization', tok1, '');

  expect(iter, tokens.BLANK, '');

  const tok2 = expect(iter, tokens.STRING, '');

  let size;
  try {
    size = util.parseU32(tok2.string);
  } catch (e) {
    throw new ParseError('bad rfc3597 serialization', tok2, '');
  }

  const [hex, tok3] = concat(iter, '');

  if (size !== (hex.length >>> 1))
    throw new ParseError('invalid rfc3597 size', tok2, '');

  let data;
  try {
    data = util.parseHex(hex);
  } catch (e) {
    throw new ParseError('invalid rfc3597 hex', tok3, '');
  }

  od.decode(data);

  return [op, tok3.comment];
}

function readString(wire, rd, type, iter, origin, file) {
  assert(rd && typeof rd === 'object');
  assert((type >>> 0) === type);
  assert(iter && typeof iter.next === 'function');
  assert(typeof origin === 'string');
  assert(typeof file === 'string');

  switch (type) {
    case schema.NAME: {
      const tok = expect(iter, tokens.STRING, file);

      let name;
      try {
        name = normalize(tok.string, origin);
      } catch (e) {
        throw new ParseError('invalid name', tok, file);
      }

      return [name, skip(iter, file)];
    }

    case schema.SERVERS: {
      const names = [];
      const [items, tok] = collect(iter, file);

      for (const item of items) {
        let name;

        try {
          name = normalize(item, origin);
        } catch (e) {
          throw new ParseError('bad rendezvous server', tok, file);
        }

        names.push(name);
      }

      return [names, tok.comment];
    }

    case schema.INET4: {
      const tok = expect(iter, tokens.STRING, file);

      let ip;
      try {
        ip = IP.toBuffer(tok.string);
      } catch (e) {
        throw new ParseError('invalid ipv4', tok, file);
      }

      if (!IP.isIPv4(ip))
        throw new ParseError('invalid ipv4', tok, file);

      return [IP.toString(ip), skip(iter, file)];
    }

    case schema.INET6: {
      const tok = expect(iter, tokens.STRING, file);

      let ip;
      try {
        ip = IP.toBuffer(tok.string);
      } catch (e) {
        throw new ParseError('invalid ipv6', tok, file);
      }

      if (IP.isIPv4(ip))
        return `::ffff:${IP.toString(ip)}`;

      return [IP.toString(ip), skip(iter, file)];
    }

    case schema.INET: {
      const tok = expect(iter, tokens.STRING, file);

      let ip;
      try {
        ip = IP.normalize(tok.string);
      } catch (e) {
        throw new ParseError('invalid ip', tok, file);
      }

      return [ip, skip(iter, file)];
    }

    case schema.TARGET: {
      const tok = expect(iter, tokens.STRING, file);

      let ip;
      try {
        ip = IP.normalize(tok.string);
      } catch (e) {
        ;
      }

      if (ip)
        return [ip, skip(iter, file)];

      let name;
      try {
        name = normalize(tok.string, origin);
      } catch (e) {
        throw new ParseError('invalid name', tok, file);
      }

      return [name, skip(iter, file)];
    }

    case schema.HEX: {
      const tok = expect(iter, tokens.STRING, file);

      if (tok.string === '-')
        return [DUMMY, skip(iter, file)];

      let data;
      try {
        data = util.parseHex(tok.string);
      } catch (e) {
        throw new ParseError('invalid hex string', tok, file);
      }

      return [data, skip(iter, file)];
    }

    case schema.HEXEND: {
      const [str, tok] = concat(iter, file);

      if (str === '-')
        return [DUMMY, tok.comment];

      let data;
      try {
        data = util.parseHex(str);
      } catch (e) {
        throw new ParseError('invalid hex string', tok, file);
      }

      return [data, tok.comment];
    }

    case schema.BASE32: {
      const tok = expect(iter, tokens.STRING, file);

      if (tok.string === '-')
        return [DUMMY, skip(iter, file)];

      let data;
      try {
        data = base32.decodeHex(tok.string);
      } catch (e) {
        throw new ParseError('invalid base32 string', tok, file);
      }

      return [data, skip(iter, file)];
    }

    case schema.BASE64: {
      const tok = expect(iter, tokens.STRING, file);

      if (tok.string === '-')
        return [DUMMY, skip(iter, file)];

      let data;
      try {
        data = util.parseB64(tok.string);
      } catch (e) {
        throw new ParseError('invalid base64 string', tok, file);
      }

      return [data, skip(iter, file)];
    }

    case schema.BASE64END: {
      const [str, tok] = concat(iter, file);

      if (str === '-')
        return [DUMMY, tok.comment];

      let data;
      try {
        data = util.parseB64(str);
      } catch (e) {
        throw new ParseError('invalid base64 string', tok, file);
      }

      return [data, tok.comment];
    }

    case schema.CHAR: {
      expect(iter, tokens.QUOTE, file);

      const tok = read(iter, file);

      if (tok.type === tokens.QUOTE)
        return ['', skip(iter, file)];

      if (tok.type !== tokens.STRING)
        throw new ParseError('invalid character string', tok, file);

      expect(iter, tokens.QUOTE, file);

      if (!encoding.isString(tok.string, false))
        throw new ParseError('invalid character string', tok, file);

      return [tok.string, skip(iter, file)];
    }

    case schema.OCTET: {
      const tok = expect(iter, tokens.STRING, file);

      if (!encoding.isString(tok.string, true))
        throw new ParseError('invalid octet string', tok, file);

      return [tok.string, skip(iter, file)];
    }

    case schema.TXT: {
      const txt = [];

      let quote = false;
      let empty = false;
      let tok;

      for (;;) {
        tok = read(iter, file);

        if (tok.end())
          break;

        switch (tok.type) {
          case tokens.STRING: {
            empty = false;
            if (!encoding.isString(tok.string, false))
              throw new ParseError('invalid txt string', tok, file);
            txt.push(tok.string);
            break;
          }
          case tokens.BLANK: {
            if (quote)
              throw new ParseError('invalid txt', tok, file);
            break;
          }
          case tokens.QUOTE: {
            if (empty && quote)
              txt.push('');
            quote = !quote;
            empty = true;
            break;
          }
          default: {
            throw new ParseError('unexpected token', tok, file);
          }
        }
      }

      if (quote)
        throw new ParseError('unclosed txt quote', tok, file);

      return [txt, tok.comment];
    }

    case schema.NSEC: {
      const [items, tok] = collect(iter, file);
      const types = items.map(s => stringToType(s));
      const map = encoding.toBitmap(types);
      return [map, tok.comment];
    }

    case schema.TAGS: {
      const [items, tok] = collect(iter, file);
      const tags = items.map(s => util.parseU16(s));
      return [tags, tok.comment];
    }

    case schema.TIME: {
      const tok = expect(iter, tokens.STRING, file);
      const time = util.parseTime(tok.string);
      return [time, skip(iter, file)];
    }

    case schema.TYPE: {
      const tok = expect(iter, tokens.STRING, file);
      const type = stringToType(tok.string);
      return [type, skip(iter, file)];
    }

    case schema.U8: {
      const tok = expect(iter, tokens.STRING, file);
      const num = util.parseU8(tok.string);
      return [num, skip(iter, file)];
    }

    case schema.U16: {
      const tok = expect(iter, tokens.STRING, file);
      const num = util.parseU16(tok.string);
      return [num, skip(iter, file)];
    }

    case schema.U32: {
      const tok = expect(iter, tokens.STRING, file);
      const num = util.parseU32(tok.string);
      return [num, skip(iter, file)];
    }

    case schema.U48: {
      const tok = expect(iter, tokens.STRING, file);
      const num = util.parseU48(tok.string);
      return [num, skip(iter, file)];
    }

    case schema.U64: {
      const tok = expect(iter, tokens.STRING, file);
      const [hi, lo] = util.parseU64(tok.string);
      const num = Buffer.allocUnsafe(8);
      bio.writeU32BE(num, hi, 0);
      bio.writeU32BE(num, lo, 4);
      return [num, skip(iter, file)];
    }

    case schema.NID32: {
      const tok = expect(iter, tokens.STRING, file);
      const nid = parseNID32(tok.string);
      return [nid, skip(iter, file)];
    }

    case schema.NID64: {
      const tok = expect(iter, tokens.STRING, file);
      const nid = parseNID64(tok.string);
      return [nid, skip(iter, file)];
    }

    case schema.EUI48: {
      const tok = expect(iter, tokens.STRING, file);
      const eui = parseEUI(tok.string, 6);
      return [eui, skip(iter, file)];
    }

    case schema.EUI64: {
      const tok = expect(iter, tokens.STRING, file);
      const eui = parseEUI(tok.string, 8);
      return [eui, skip(iter, file)];
    }

    case schema.APL: {
      const {AP} = wire;
      const [items, tok] = collect(iter, file);
      const ap = items.map(s => AP.fromString(s));
      return [ap, tok.comment];
    }

    case schema.NSAP: {
      const tok = expect(iter, tokens.STRING, file);
      const nsap = parseNSAP(tok.string);
      return [nsap, skip(iter, file)];
    }

    case schema.ATMA: {
      const tok = expect(iter, tokens.STRING, file);
      const atma = parseATMA(tok.string, rd.format);
      return [atma, skip(iter, file)];
    }

    case schema.PROTOCOL: {
      const tok = expect(iter, tokens.STRING, file);
      const prot = parseProtocol(tok.string);
      return [prot, skip(iter, file)];
    }

    case schema.WKS: {
      const [services, tok] = collect(iter, file);
      const map = parseWKS(services);
      return [map, tok.comment];
    }

    case schema.TTL: {
      const tok = expect(iter, tokens.STRING, file);
      const num = stringToTTL(tok.string);
      return [num, skip(iter, file)];
    }

    default: {
      throw new ParseError('unknown schema type', null, file);
    }
  }
}

/*
 * API
 */

function parseZone(wire, input, origin, file) {
  assert(wire && typeof wire.fromZone === 'function');
  assert(typeof input === 'string');

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

function parseRecord(wire, input) {
  assert(wire && typeof wire.fromZone === 'function');
  assert(typeof input === 'string');

  const def = new TTLState(DEFAULT_TTL, false);
  const iter = parser(wire, input, '', '', def, 1);
  const it = iter.next();

  if (it.done)
    throw new ParseError('no record');

  const item = it.value;

  if (item.error)
    throw item.error;

  return item.record;
}

function parseData(wire, type, input) {
  assert(wire && typeof wire.fromZone === 'function');
  assert((type & 0xffff) === type);
  assert(typeof input === 'string');

  const typeName = typeToString(type);
  const str = `. 0 IN ${typeName} ${input}`;

  return parseRecord(wire, str).data;
}

function parseOption(wire, input) {
  assert(wire && typeof wire.fromZone === 'function');
  assert(typeof input === 'string');

  const iter = lexer(input, false);

  let tok = expect(iter, tokens.STRING);

  if (tok.string[tok.string.length - 1] === ':')
    tok.string = tok.string.slice(0, -1);

  let code = options[tok.string.toUpperCase()];
  let unknown = false;

  if ((code & 0xffff) !== code) {
    try {
      code = stringToOption(tok.string);
    } catch (e) {
      throw new ParseError('unknown option', tok);
    }
    unknown = true;
  }

  tok = read(iter);

  if (tok.type !== tokens.BLANK && !tok.end())
    throw new ParseError('unexpected token', tok);

  const parse = unknown ? readUnknownOption : readOption;
  const [option] = parse(wire, iter, code);

  return option;
}

function parseOptionData(wire, code, input) {
  assert(wire && typeof wire.fromZone === 'function');
  assert((code & 0xffff) === code);
  assert(typeof input === 'string');

  const codeName = optionToString(code);
  const str = `${codeName}: ${input}`;

  return parseOption(wire, str).option;
}

/*
 * Helpers
 */

function read(iter, file) {
  const it = iter.next();

  if (it.done) {
    const tok = new Token();
    tok.type = tokens.EOF;
    return tok;
  }

  const tok = it.value;

  if (tok.error)
    throw new ParseError(tok.string, tok, file, read);

  return tok;
}

function expect(iter, type, file) {
  const tok = read(iter, file);

  if (tok.type !== type)
    throw new ParseError('unexpected token', tok, expect);

  return tok;
}

function collect(iter, file) {
  const items = [];

  let tok;

  for (;;) {
    tok = read(iter, file);

    if (tok.end())
      break;

    switch (tok.type) {
      case tokens.BLANK:
        break;
      case tokens.STRING:
        items.push(tok.string);
        break;
      default:
        throw new ParseError('unexpected token', tok, file);
    }
  }

  return [items, tok];
}

function concat(iter, file) {
  let str = '';
  let tok;

  for (;;) {
    tok = read(iter, file);

    if (tok.end())
      break;

    switch (tok.type) {
      case tokens.BLANK:
        break;
      case tokens.STRING:
        str += tok.string;
        break;
      default:
        throw new ParseError('unexpected token', tok, file);
    }
  }

  return [str, tok];
}

function slurp(iter, file) {
  const tok = read(iter, file);

  switch (tok.type) {
    case tokens.BLANK: {
      const tok = read(iter, file);

      if (tok.type !== tokens.NEWLINE && tok.type !== tokens.EOF)
        throw new ParseError('garbage after rdata', tok, file);

      return tok.comment;
    }

    case tokens.EOF:
    case tokens.NEWLINE: {
      return tok.comment;
    }

    default: {
      throw new ParseError('garbage after rdata', tok, file);
    }
  }
}

function skip(iter, file) {
  const tok = read(iter, file);

  switch (tok.type) {
    case tokens.EOF:
    case tokens.NEWLINE:
    case tokens.BLANK: {
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

  if (str.length === 0 || str.length > 10)
    throw new Error('Invalid TTL.');

  for (let i = 0; i < str.length; i++) {
    const ch = str.charCodeAt(i);

    switch (ch) {
      case 0x73 /*s*/:
      case 0x53 /*S*/:
        s += w;
        w = 0;
        break;
      case 0x6d /*m*/:
      case 0x4d /*M*/:
        s += w * 60;
        w = 0;
        break;
      case 0x68 /*h*/:
      case 0x48 /*H*/:
        s += w * 60 * 60;
        w = 0;
        break;
      case 0x64 /*d*/:
      case 0x44 /*D*/:
        s += w * 60 * 60 * 24;
        w = 0;
        break;
      case 0x77 /*w*/:
      case 0x57 /*W*/:
        s += w * 60 * 60 * 24 * 7;
        w = 0;
        break;
      case 0x30 /*0*/:
      case 0x31 /*1*/:
      case 0x32 /*2*/:
      case 0x33 /*3*/:
      case 0x34 /*4*/:
      case 0x35 /*5*/:
      case 0x36 /*6*/:
      case 0x37 /*7*/:
      case 0x38 /*8*/:
      case 0x39 /*9*/:
        w *= 10;
        w += ch - 0x30;
        break;
      default:
        throw new Error('Invalid TTL.');
    }

    if (s > 0xffffffff)
      throw new Error('Invalid TTL.');
  }

  w += s;

  if (w > 0xffffffff)
    throw new Error('Invalid TTL.');

  return w;
}

function normalize(name, origin) {
  const fqdn = toAbsoluteName(name, origin);

  if (!encoding.isName(fqdn))
    throw new Error('Bad name.');

  return fqdn;
}

function toAbsoluteName(name, origin) {
  if (origin == null)
    origin = '';

  assert(typeof name === 'string');
  assert(typeof origin === 'string');

  if (name === '@') {
    if (origin === '')
      throw new Error('Bad origin.');

    return origin;
  }

  if (name === '')
    throw new Error('Bad name.');

  if (util.isFQDN(name))
    return name;

  if (origin === '')
    throw new Error('Bad origin.');

  return appendOrigin(name, origin);
}

function appendOrigin(name, origin) {
  if (origin == null)
    origin = '';

  assert(typeof name === 'string');
  assert(typeof origin === 'string');

  if (origin === '.')
    return name + origin;

  return `${name}.${origin}`;
}

function parseNID32(str) {
  assert(typeof str === 'string');

  const data = IP.toBuffer(str);

  if (!IP.isIPv4(data))
    throw new Error('Invalid NID32.');

  return data.slice(12, 16);
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

function parseNSAP(str) {
  assert(typeof str === 'string');
  assert(str.length >= 2);
  assert(str[0] === '0');
  assert(str[1] === 'x' || str[1] === 'X');

  const s = str.substring(2);
  const hex = s.replace(/\./g, '');

  return util.parseHex(hex);
}

function parseATMA(str, format) {
  assert(typeof str === 'string');

  // Whoever designed the presentation
  // for this one has severe brain damage.
  // The `format` byte decides the format!
  // 0 = AESA / ISO8348/AD2 a.k.a NSAP
  // 1 = E.164 a.k.a Keypad Style (7bit IA5)
  switch (format) {
    case 0: {
      // Note: no leading 0x.
      const hex = str.replace(/\./g, '');
      return util.parseHex(hex);
    }
    case 1: {
      // Technically IA5.
      return Buffer.from(str, 'ascii');
    }
    default: {
      // The geniuses specifying ATMA
      // didn't specify how to present
      // unknown formats. Just use hex.
      return util.parseHex(str);
    }
  }
}

function parseProtocol(str) {
  const iana = lazy('./iana');
  return iana.stringToProtocol(str);
}

function parseWKS(names) {
  assert(Array.isArray(names));

  const iana = lazy('./iana');
  const ports = [];

  for (const name of names) {
    const port = iana.getPort(name);

    if (port === 0)
      continue;

    ports.push(port);
  }

  return encoding.toPortmap(ports);
}

function hasM(str) {
  assert(typeof str === 'string');

  const len = str.length;

  if (len === 0)
    return false;

  const ch = str.charCodeAt(len - 1);

  return ch === 0x4d /*M*/ || ch === 0x6d /*m*/;
}

function stringToCM(str) {
  assert(typeof str === 'string');

  if (hasM(str))
    str = str.slice(0, -1);

  const s = str.split('.', 3);
  assert(s.length >= 1);

  let meters = 0;
  let cmeters = 0;

  switch (s.length) {
    case 3:
      throw new Error('Invalid integer.');
    case 2:
      cmeters = parseInt(s[1]);
    case 1:
      meters = parseInt(s[0]);
      break;
  }

  if (!isFinite(meters) || !isFinite(cmeters))
    throw new Error('Invalid integer.');

  let e = 0;
  let val = cmeters;

  if (meters > 0) {
    e = 2;
    val = meters;
  }

  while (val > 10) {
    e += 1;
    val -= val % 10;
    val /= 10;
  }

  if (e > 9)
    throw new Error('Invalid exponent.');

  const m = val & 0xff;

  return [e, m];
}

function locCheckNorth(token, latitude) {
  switch (token) {
    case 'n':
    case 'N':
      return [LOC_EQUATOR + latitude, true];
    case 's':
    case 'S':
      return [LOC_EQUATOR - latitude, false];
  }
  return [latitude, false];
}

function locCheckEast(token, longitude) {
  switch (token) {
    case 'e':
    case 'E':
      return [LOC_PRIMEMERIDIAN + longitude, true];
    case 'w':
    case 'W':
      return [LOC_PRIMEMERIDIAN - longitude, true];
  }
  return [longitude, false];
}

function parseLOC(rd, iter, file) {
  assert(rd && typeof rd === 'object');
  assert(iter && typeof iter.next === 'function');

  let ok, tok;

  // Defaults.
  rd.horizPre = 165; // 10000
  rd.vertPre = 162; // 10
  rd.size = 18; // 1

  // North.
  tok = expect(iter, tokens.STRING, file);

  const lat = util.parseU32(tok.string);

  rd.latitude = 1000 * 60 * 60 * lat;
  rd.latitude >>>= 0;

  expect(iter, tokens.BLANK, file);

  tok = expect(iter, tokens.STRING, file);

  [rd.latitude, ok] = locCheckNorth(tok.string, rd.latitude);

  if (!ok) {
    const lat = util.parseU32(tok.string);

    rd.latitude += 1000 * 60 * lat;
    rd.latitude >>>= 0;

    expect(iter, tokens.BLANK, file);

    tok = expect(iter, tokens.STRING, file);

    const sec = parseFloat(tok.string);

    if (!isFinite(sec))
      throw new ParseError('bad LOC latitude seconds', tok, file);

    rd.latitude += (1000 * sec) >>> 0;
    rd.latitude >>>= 0;

    expect(iter, tokens.BLANK, file);

    tok = expect(iter, tokens.STRING, file);

    [rd.latitude, ok] = locCheckNorth(tok.string, rd.latitude);

    if (!ok)
      throw new ParseError('bad LOC latitude north/south', tok, file);
  }

  // East.
  expect(iter, tokens.BLANK, file);

  tok = expect(iter, tokens.STRING, file);

  const lon = util.parseU32(tok.string);

  rd.longitude = 1000 * 60 * 60 * lon;
  rd.longitude >>>= 0;

  expect(iter, tokens.BLANK, file);

  tok = expect(iter, tokens.STRING, file);

  [rd.longitude, ok] = locCheckEast(tok.string, rd.longitude);

  if (!ok) {
    const lon = util.parseU32(tok.string);

    rd.longitude += 1000 * 60 * lon;
    rd.longitude >>>= 0;

    expect(iter, tokens.BLANK, file);

    tok = expect(iter, tokens.STRING, file);

    const sec = parseFloat(tok.string);

    if (!isFinite(sec))
      throw new ParseError('bad LOC longitude seconds', tok, file);

    rd.longitude += (1000 * sec) >>> 0;
    rd.longitude >>>= 0;

    expect(iter, tokens.BLANK, file);

    tok = expect(iter, tokens.STRING, file);

    [rd.longitude, ok] = locCheckEast(tok.string, rd.longitude);

    if (!ok)
      throw new ParseError('bad LOC latitude east/west', tok, file);
  }

  // Altitude.
  expect(iter, tokens.BLANK, file);

  tok = expect(iter, tokens.STRING, file);

  if (hasM(tok.string))
    tok.string = tok.string.slice(0, -1);

  const alt = parseFloat(tok.string);

  if (!isFinite(alt))
    throw new ParseError('bad LOC altitude', tok, file);

  rd.altitude = alt * 100.0 + 10000000.0 + 0.5;
  rd.altitude >>>= 0;

  // Params
  let count = 0;

  for (;;) {
    tok = read(iter, file);

    if (tok.end())
      break;

    switch (tok.type) {
      case tokens.STRING: {
        switch (count) {
          case 0: {
            const [e, m] = stringToCM(tok.string);
            rd.size = (e & 0x0f) | ((m << 4) & 0xf0);
            break;
          }
          case 1: {
            const [e, m] = stringToCM(tok.string);
            rd.horizPre = (e & 0x0f) | ((m << 4) & 0xf0);
            break;
          }
          case 2: {
            const [e, m] = stringToCM(tok.string);
            rd.vertPre = (e & 0x0f) | ((m << 4) & 0xf0);
            break;
          }
        }
        count += 1;
        break;
      }
      case tokens.BLANK: {
        break;
      }
      default: {
        throw new ParseError('unexpected token', tok, file);
      }
    }
  }

  return tok.comment;
}

/*
 * Expose
 */

exports.parseZone = parseZone;
exports.parseRecord = parseRecord;
exports.parseData = parseData;
exports.parseOption = parseOption;
exports.parseOptionData = parseOptionData;
