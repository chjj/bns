/* eslint-env mocha */
/* eslint prefer-arrow-callback: "off" */

'use strict';

const assert = require('./util/assert');
const constants = require('../lib/constants');

const {
  opcodes,
  opcodeToString,
  stringToOpcode,
  isOpcodeString,

  codes,
  codeToString,
  stringToCode,
  isCodeString,

  types,
  typeToString,
  stringToType,
  isTypeString,

  classes,
  classToString,
  stringToClass,
  isClassString,

  algs,
  algToString,
  stringToAlg,
  isAlgString
} = constants;

describe('Constants', function() {
  it('should convert types', () => {
    assert.strictEqual(opcodeToString(opcodes.QUERY), 'QUERY');
    assert.strictEqual(stringToOpcode('QUERY'), opcodes.QUERY);
    assert.strictEqual(stringToOpcode(`OPCODE${opcodes.QUERY}`), opcodes.QUERY);
    assert.strictEqual(isOpcodeString('QUERY'), true);
    assert.strictEqual(isOpcodeString('QUERY_'), false);

    assert.strictEqual(codeToString(codes.NXDOMAIN), 'NXDOMAIN');
    assert.strictEqual(stringToCode('NXDOMAIN'), codes.NXDOMAIN);
    assert.strictEqual(stringToCode(`RCODE${codes.NXDOMAIN}`), codes.NXDOMAIN);
    assert.strictEqual(isCodeString('NXDOMAIN'), true);
    assert.strictEqual(isCodeString('NXDOMAIN_'), false);

    assert.strictEqual(typeToString(types.AAAA), 'AAAA');
    assert.strictEqual(stringToType('AAAA'), types.AAAA);
    assert.strictEqual(stringToType(`TYPE${types.AAAA}`), types.AAAA);
    assert.strictEqual(isTypeString('AAAA'), true);
    assert.strictEqual(isTypeString('AAAA_'), false);

    assert.strictEqual(classToString(classes.IN), 'IN');
    assert.strictEqual(stringToClass('IN'), classes.IN);
    assert.strictEqual(stringToClass(`CLASS${classes.IN}`), classes.IN);
    assert.strictEqual(isClassString('IN'), true);
    assert.strictEqual(isClassString('IN_'), false);

    assert.strictEqual(algToString(algs.RSASHA256), 'RSASHA256');
    assert.strictEqual(stringToAlg('RSASHA256'), algs.RSASHA256);
    assert.strictEqual(stringToAlg(`ALG${algs.RSASHA256}`), algs.RSASHA256);
    assert.strictEqual(isAlgString('RSASHA256'), true);
    assert.strictEqual(isAlgString('RSASHA256_'), false);
  });
});
