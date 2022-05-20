/* eslint-env mocha */
/* eslint prefer-arrow-callback: "off" */

'use strict';

const assert = require('bsert');
const Path = require('path');
const fs = require('bfile');
const wire = require('../lib/wire');
const Zone = require('../lib/zone');
const {types, codes} = wire;

const ROOT_ZONE = Path.resolve(__dirname, 'data', 'root.zone');
const COM_RESPONSE = Path.resolve(__dirname, 'data', 'com-response.zone');
const COM_GLUE = Path.resolve(__dirname, 'data', 'com-glue.zone');
const NX_RESPONSE = Path.resolve(__dirname, 'data', 'nx-response.zone');

const comResponse = fs.readFileSync(COM_RESPONSE, 'utf8');
const comGlue = fs.readFileSync(COM_GLUE, 'utf8');
const nxResponse = fs.readFileSync(NX_RESPONSE, 'utf8');

describe('Zone', function() {
  this.timeout(10000);

  it('should serve root zone', () => {
    const zone = Zone.fromFile('.', ROOT_ZONE);

    assert.strictEqual(zone.names.size, 7044);

    {
      const msg = zone.resolve('com.', types.NS);
      assert(msg.code === codes.NOERROR);
      assert(!msg.aa);

      const expect = wire.fromZone(comResponse);

      assert.deepStrictEqual(msg.authority, expect);

      const glue = wire.fromZone(comGlue);

      assert.deepStrictEqual(msg.additional, glue);
    }

    {
      const msg = zone.resolve('idontexist.', types.A);
      assert(msg.code === codes.NXDOMAIN);
      assert(!msg.aa);
      assert(msg.answer.length === 0);

      const expect = wire.fromZone(nxResponse);

      assert.deepStrictEqual(msg.authority, expect);
    }
  });
});
