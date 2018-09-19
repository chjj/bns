/* eslint-env mocha */
/* eslint prefer-arrow-callback: "off" */

'use strict';

const assert = require('./util/assert');
const Path = require('path');
const fs = require('bfile');
const wire = require('../lib/wire');
const Zone = require('../lib/zone');
const {types, codes} = wire;

const ROOT_ZONE = Path.resolve(__dirname, 'data', 'root.zone');
const COM_RESPONSE = Path.resolve(__dirname, 'data', 'com-response.zone');
const NX_RESPONSE = Path.resolve(__dirname, 'data', 'nx-response.zone');

const comResponse = fs.readFileSync(COM_RESPONSE, 'utf8');
const nxResponse = fs.readFileSync(NX_RESPONSE, 'utf8');

describe('Zone', function() {
  it('should serve root zone', () => {
    const zone = Zone.fromFile('.', ROOT_ZONE);

    assert.strictEqual(zone.names.size, 5717);

    {
      const msg = zone.resolve('com.', types.NS);
      assert(msg.code === codes.NOERROR);

      const expect = wire.fromZone(comResponse);

      assert.deepStrictEqual(msg.answer, expect);
    }

    {
      const msg = zone.resolve('idontexist.', types.A);
      assert(msg.code === codes.NXDOMAIN);
      assert(msg.answer.length === 0);

      const expect = wire.fromZone(nxResponse);

      assert.deepStrictEqual(msg.authority, expect);
    }
  });
});
