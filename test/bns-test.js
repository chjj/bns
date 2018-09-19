/* eslint-env mocha */
/* eslint prefer-arrow-callback: "off" */

'use strict';

const assert = require('./util/assert');

describe('BNS', function() {
  it('should require BNS', () => {
    const bns = require('../');
    assert(bns);
  });
});
