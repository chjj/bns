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

    assert.strictEqual(zone.names.size, 5717);

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

  describe('Serve records from zone', function() {
    const zone = new Zone();
    const domain = 'thebnszone.';
    const subdomainWithGlue = 'subdomain-glue.' + domain;
    const subdomainNoGlue = 'subdomain-external.' + domain;
    const subdomainWithText = 'subdomain-text.' + domain;

    // TLD
    zone.setOrigin(domain);
    // A record for TLD (Common in Handshake, not in DNS)
    zone.fromString(`${domain} 21600 IN A 10.20.30.40`);
    // TXT record for TLD
    zone.fromString(`${subdomainWithText} 21600 IN TXT "subdomain-with-text"`);
    // TXT for wildcard
    zone.fromString('* 21600 IN TXT "wildcard"');
    // CNAME for subdomain -> TLD
    zone.fromString(`${subdomainWithGlue} 21600 IN CNAME ${domain}`);
    // CNAME for subdomain -> other zone
    zone.fromString(`${subdomainNoGlue} 21600 IN CNAME idontexist.`);
    // SOA to trigger authority flag
    zone.fromString(
      `${domain} 21600 IN SOA ns1.${domain} admin.${domain} ` +
      '2020070500 86400 7200 604800 300'
    );

    it('should serve A record', () => {
      const msg = zone.resolve(domain, types.A);
      assert(msg.code === codes.NOERROR);
      assert(msg.aa);
      assert(msg.authority.length === 0);
      assert(msg.additional.length === 0);
      assert(msg.answer.length === 1);
      assert(msg.answer[0].data.address = '10.20.30.40');
    });

    it('should serve SOA record for missing type', () => {
      const msg = zone.resolve(domain, types.AAAA);
      assert(msg.code === codes.NOERROR);
      assert(msg.aa);
      assert(msg.authority.length === 1);
      assert(msg.additional.length === 0);
      assert(msg.answer.length === 0);
    });

    it('should serve TXT record for wildcard', () => {
      const msg = zone.resolve(`idontexist.${domain}`, types.TXT);
      assert(msg.code === codes.NOERROR);
      assert(!msg.aa);
      assert(msg.authority.length === 0);
      assert(msg.additional.length === 0);
      assert(msg.answer.length === 1);
      assert(msg.answer[0].data.txt.length === 1);
      assert(msg.answer[0].data.txt[0] === 'wildcard' );
    });

    it('should serve TXT record for defined subdomain', () => {
      const msg = zone.resolve(`${subdomainWithText}`, types.TXT);
      assert(msg.code === codes.NOERROR);
      assert(!msg.aa);
      assert(msg.authority.length === 0);
      assert(msg.additional.length === 0);
      assert(msg.answer.length === 1);
      assert(msg.answer[0].data.txt.length === 1);
      assert(msg.answer[0].data.txt[0] === 'subdomain-with-text');
    });

    for (const t of Object.keys(types)) {
      it(`should serve CNAME + glue as answers for type: ${t}`, () => {
        if (t === 'NS' || t === 'ANY' || t === 'UNKNOWN' || t === 'SOA')
          this.skip(); // TODO

        const msg = zone.resolve(subdomainWithGlue, types[t]);
        assert(msg.code === codes.NOERROR);
        assert(!msg.aa);
        assert(msg.authority.length === 0);
        assert(msg.additional.length === 0);

        if (t !== 'A') {
          assert(msg.answer.length === 1);
          assert(msg.answer[0].type === types.CNAME);
        } else {
          let cname = false;
          let a = false;
          for (const an of msg.answer) {
            if (an.type === types.CNAME)
              cname = true;

            if (an.type === types.A) {
              a = true;
              assert (an.data.address = '10.20.30.40');
            }
          }
          assert(cname);
          assert(a);
        }
      });
    }

    for (const t of Object.keys(types)) {
      it(`should serve CNAME only for type: ${t}`, () => {
        if (t === 'NS' || t === 'ANY')
          this.skip(); // TODO

        const msg = zone.resolve(subdomainNoGlue, types[t]);
        assert(msg.code === codes.NOERROR);
        assert(!msg.aa);
        assert(msg.authority.length === 0);
        assert(msg.additional.length === 0);
        assert(msg.answer.length === 1);
        assert(msg.answer[0].type = types.CNAME);
        assert(msg.answer[0].data.target = 'idontexist.');
      });
    }
  });

  describe('CNAME for wildcard', function() {
    const zone = new Zone();
    const domain = 'thebnszone.';
    const subdomainWithGlue = 'subdomain-glue.' + domain;

    // TLD
    zone.setOrigin(domain);
    // Reset zone.
    zone.clearRecords();
    // A record for TLD (Common in Handshake, not in DNS)
    zone.fromString(`${domain} 21600 IN A 10.20.30.40`);
    // CNAME for wildcard -> TXT
    zone.fromString(`* 21600 IN CNAME ${domain}`);

    for (const t of Object.keys(types)) {
      it(`should serve CNAME + glue as answers for type: ${t}`, () => {
        if (t === 'NS' || t === 'ANY' || t === 'UNKNOWN')
          this.skip(); // TODO

        const msg = zone.resolve(subdomainWithGlue, types[t]);
        assert(msg.code === codes.NOERROR);
        assert(!msg.aa);
        assert(msg.authority.length === 0);
        assert(msg.additional.length === 0);

        if (t !== 'A') {
          assert(msg.answer.length === 1);
          assert(msg.answer[0].type === types.CNAME);
        } else {
          let cname = false;
          let a = false;
          for (const an of msg.answer) {
            if (an.type === types.CNAME)
              cname = true;

            if (an.type === types.A) {
              a = true;
              assert (an.data.address = '10.20.30.40');
            }
          }
          assert(cname);
          assert(a);
        }
      });
    }
  });
});
