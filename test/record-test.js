/* eslint-env mocha */
/* eslint prefer-arrow-callback: "off" */

'use strict';

const assert = require('bsert');
const wire = require('../lib/wire');
const {Record} = wire;

// $ dig SW1A2AA.find.me.uk. LOC
const locTxt = 'SW1A2AA.find.me.uk. 2592000 IN LOC'
  + ' 51 30 12.748 N 0 7 39.611 W 0.00m 0.00m 0.00m 0.00m';

// $ dig apple.com. NAPTR
const naptr = [
  'apple.com. 86400 IN NAPTR 50 50 "se" "SIPS+D2T" "" _sips._tcp.apple.com.',
  'apple.com. 86400 IN NAPTR 90 50 "se" "SIP+D2T" "" _sip._tcp.apple.com.',
  'apple.com. 86400 IN NAPTR 100 50 "se" "SIP+D2U" "" _sip._udp.apple.com.'
];

describe('Record', function() {
  it('should parse LOC record', () => {
    const rr = Record.fromString(locTxt);
    assert.strictEqual(rr.toString(), locTxt);
  });

  it('should parse NAPTR records', () => {
    for (const txt of naptr) {
      const rr = Record.fromString(txt);
      assert.strictEqual(rr.toString(), txt);
    }
  });
});
