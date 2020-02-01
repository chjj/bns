/* eslint-env mocha */
/* eslint prefer-arrow-callback: "off" */

'use strict';

const assert = require('bsert');
const wire = require('../lib/wire');
const {Record, DNSKEYRecord} = wire;

// $ dig SW1A2AA.find.me.uk. LOC
const locTxt = 'SW1A2AA.find.me.uk. 2592000 IN LOC'
  + ' 51 30 12.748 N 0 7 39.611 W 0.00m 0.00m 0.00m 0.00m';

// $ dig apple.com. NAPTR
const naptr = [
  'apple.com. 86400 IN NAPTR 50 50 "se" "SIPS+D2T" "" _sips._tcp.apple.com.',
  'apple.com. 86400 IN NAPTR 90 50 "se" "SIP+D2T" "" _sip._tcp.apple.com.',
  'apple.com. 86400 IN NAPTR 100 50 "se" "SIP+D2U" "" _sip._udp.apple.com.'
];

// $ dig . DNSKEY +dnssec
const prefix = '. 172800 IN DNSKEY';
const keyTxt = ' 385 3 8'
  + ' AwEAAagAIKlVZrpC6Ia7gEzahOR+9W29euxhJhVVLOyQbSEW0O8gcCjF'
  + ' FVQUTf6v58fLjwBd0YI0EzrAcQqBGCzh/RStIoO8g0NfnfL2MTJRkxoX'
  + ' bfDaUeVPQuYEhg37NZWAJQ9VnMVDxP/VHL496M/QZxkjf5/Efucp2gaD'
  + ' X6RS6CXpoY68LsvPVjR0ZSwzz1apAzvN9dlzEheX7ICJBBtuA6G3LQpz'
  + ' W5hOA2hzCTMjJPJ8LbqF6dsV6DoBQzgul0sGIcGOYl7OyQdXfZ57relS'
  + ' Qageu+ipAdTTJ25AsRTAoub8ONGcLmqrAmRLKBP1dfwhYB4N7knNnulq'
  + '  QxA+Uk1ihz0=  ; KSK ; alg = RSASHA256 ; bits = 2048,17 ; key id = 19164';

const keyJSON =
  {
    name: '.',
    ttl: 172800,
    class: 'IN',
    type: 'DNSKEY',
    data: {
      flags: 385,
      protocol: 3,
      algorithm: 8,
      publicKey: 'AwEAAagAIKlVZrpC6Ia7gEzahOR+9W29euxhJhVVLOyQbSEW0O8gcCjF'
        + 'FVQUTf6v58fLjwBd0YI0EzrAcQqBGCzh/RStIoO8g0NfnfL2MTJRkxoX'
        + 'bfDaUeVPQuYEhg37NZWAJQ9VnMVDxP/VHL496M/QZxkjf5/Efucp2gaD'
        + 'X6RS6CXpoY68LsvPVjR0ZSwzz1apAzvN9dlzEheX7ICJBBtuA6G3LQpz'
        + 'W5hOA2hzCTMjJPJ8LbqF6dsV6DoBQzgul0sGIcGOYl7OyQdXfZ57relS'
        + 'Qageu+ipAdTTJ25AsRTAoub8ONGcLmqrAmRLKBP1dfwhYB4N7knNnulqQxA+Uk1ihz0=',
      keyType: 'KSK',
      keyTag: 19164,
      algName: 'RSASHA256',
      bits: [2048, 17]
    }
  };

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

  it('should parse DNSKEY record', () => {
    const rr = Record.fromString(prefix + keyTxt);
    assert.deepStrictEqual(rr.getJSON(), keyJSON);
  });

  it('should parse DNSKEY data from string', () => {
    const rr = DNSKEYRecord.fromString(keyTxt);
    assert.deepStrictEqual(rr.getJSON(), keyJSON.data);
  });
});
