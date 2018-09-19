/* eslint-env mocha */
/* eslint prefer-arrow-callback: "off" */
/* eslint no-tabs: "off" */

'use strict';

const assert = require('./util/assert');
const {types} = require('../lib/constants');
const encoding = require('../lib/encoding');
const Hosts = require('../lib/hosts');

const hostsText = `
#
# /etc/hosts: static lookup table for host names
#

#<ip-address>	<hostname.domain.org>	<hostname>
127.0.0.1	localhost.localdomain	localhost
::1		localhost.localdomain	localhost
127.0.1.1       machine.localdomain   machine

# End of file
`;

describe('Hosts', function() {
  it('should add hosts', () => {
    const hosts = Hosts.fromString(hostsText);

    {
      const answer = hosts.query('localhost.', types.A);
      assert(answer.length === 1);
      const rr = answer[0];
      assert(rr && rr.type === types.A);
      assert(rr.data.address === '127.0.0.1');
    }

    {
      const answer = hosts.query('localhost.', types.AAAA);
      assert(answer.length === 1);
      const rr = answer[0];
      assert(rr && rr.type === types.AAAA);
      assert(rr.data.address === '::1');
    }

    {
      const answer = hosts.query('localhost.', types.ANY);
      assert(answer.length === 2);

      const rr1 = answer[0];
      assert(rr1 && rr1.type === types.A);
      assert(rr1.data.address === '127.0.0.1');

      const rr2 = answer[1];
      assert(rr2 && rr2.type === types.AAAA);
      assert(rr2.data.address === '::1');
    }

    {
      const answer = hosts.query(encoding.reverse('127.0.0.1'), types.A);
      assert(answer.length === 0);
    }

    {
      const answer = hosts.query(encoding.reverse('127.0.0.1'), types.PTR);
      assert(answer.length === 1);

      const rr = answer[0];
      assert(rr && rr.type === types.PTR);
      assert(rr.data.ptr === 'localhost.');
    }

    {
      const answer = hosts.query(encoding.reverse('::1'), types.PTR);
      assert(answer.length === 1);

      const rr = answer[0];
      assert(rr && rr.type === types.PTR);
      assert(rr.data.ptr === 'localhost.');
    }

    {
      const answer = hosts.query(encoding.reverse('::2'), types.PTR);
      assert(!answer);
    }
  });
});
