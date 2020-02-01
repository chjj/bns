/*!
 * util.js - util tests for bns
 * Copyright (c) 2018, Christopher Jeffrey (MIT License).
 * https://github.com/chjj/bns
 *
 * Parts of this software are based on miekg/dns:
 *   https://github.com/miekg/dns/blob/master/labels_test.go
 *   https://github.com/miekg/dns/blob/master/dns_test.go
 *   https://github.com/miekg/dns/blob/master/parse_test.go
 *   https://github.com/miekg/dns/blob/master/dnsutil/util_test.go
 */

/* eslint-env mocha */
/* eslint prefer-arrow-callback: 'off' */

'use strict';

const assert = require('bsert');
const encoding = require('../lib/encoding');
const util = require('../lib/util');

describe('Util', function() {
  it('should split string', () => {
    assert.deepStrictEqual(util.splitName(''), []);
    assert.deepStrictEqual(util.splitName('.'), []);
    assert.deepStrictEqual(util.splitName('example.com'), ['example', 'com']);
    assert.deepStrictEqual(util.splitName('example.com.'), ['example', 'com']);
    assert.deepStrictEqual(util.splitName('EXAMPLE.COM.'), ['EXAMPLE', 'COM']);
  });

  it('should compare names', () => {
    const s1 = 'www.miek.nl.';
    const s2 = 'miek.nl.';
    const s3 = 'www.bla.nl.';
    const s4 = 'nl.www.bla.';
    const s5 = 'nl.';
    const s6 = 'miek.nl.';

    assert.strictEqual(util.compareName('.', '.'), 0);
    assert.strictEqual(util.compareName(s1, s2), 2);
    assert.strictEqual(util.compareName(s1, s3), 1);
    assert.strictEqual(util.compareName(s3, s4), 0);
    assert.strictEqual(util.compareName(s1, s5), 1);
    assert.strictEqual(util.compareName(s1, s6), 2);
    assert.strictEqual(util.compareName(s1, '.'), 0);
    assert.strictEqual(util.compareName('.', '.'), 0);
    assert.strictEqual(util.compareName('test.com.', 'TEST.COM.'), 2);
  });

  it('should split names', () => {
    const splits = [
      ['www.miek.nl.', 3],
      ['www.miek.nl', 3],
      ['www..miek.nl', 4],
      ['www\\.miek.nl.', 2],
      ['www\\\\.miek.nl.', 3],
      ['www\\\\\\.miek.nl.', 2],
      ['.', 0],
      ['nl.', 1],
      ['nl', 1],
      ['com.', 1],
      ['.com.', 2]
    ];

    for (const [name, expect] of splits)
      assert.strictEqual(util.split(name).length, expect, name);
  });

  it('should split names (again)', () => {
    const splits = [
      ['www.miek.nl.', [0, 4, 9]],
      ['www.miek.nl', [0, 4, 9]],
      ['nl', [0]]
    ];

    for (const [name, expect] of splits)
      assert.deepStrictEqual(util.split(name), expect, name);
  });

  it('should test nextLabel', () => {
    const nexts = [
      [['', 1], 0],
      [['www.miek.nl.', 0], 4],
      [['www.miek.nl.', 4], 9],
      [['www.miek.nl.', 9], 12]
    ];

    for (const [s, expect] of nexts) {
      const [x, ok] = util.nextLabel(s[0], s[1]);
      assert(typeof ok === 'boolean');
      assert.strictEqual(x, expect, JSON.stringify(s));
    }
  });

  it('should test prevLabel', () => {
    const prevs = [
      [['', 1], 0],
      [['www.miek.nl.', 0], 12],
      [['www.miek.nl.', 1], 9],
      [['www.miek.nl.', 2], 4],

      [['www.miek.nl', 0], 11],
      [['www.miek.nl', 1], 9],
      [['www.miek.nl', 2], 4],

      [['www.miek.nl.', 5], 0],
      [['www.miek.nl', 5],  0],

      [['www.miek.nl.', 3], 0],
      [['www.miek.nl', 3],  0]
    ];

    for (const [s, expect] of prevs) {
      const [x, ok] = util.prevLabel(s[0], s[1]);
      assert(typeof ok === 'boolean');
      assert.strictEqual(x, expect, JSON.stringify(s));
    }
  });

  it('should count labels', () => {
    const splits = [
      ['www.miek.nl.', 3],
      ['www.miek.nl', 3],
      ['nl', 1],
      ['.', 0]
    ];

    for (const [name, expect] of splits)
      assert.strictEqual(util.countLabels(name), expect, name);
  });

  it('should test previous labels', () => {
    const labels = [
      ['miek.nl', ['miek', 'nl']],
      ['.', []],
      ['www.miek.nl.', ['www', 'miek', 'nl']],
      ['www.miek.nl', ['www', 'miek', 'nl']],
      ['www..miek.nl', ['www', '', 'miek', 'nl']],
      ['www\\.miek.nl', ['www\\.miek', 'nl']],
      ['www\\\\.miek.nl', ['www\\\\', 'miek', 'nl']],
      ['.www.miek.nl.', ['', 'www', 'miek', 'nl']]
    ];

    for (const [name, expect] of labels)
      assert.deepStrictEqual(util.splitName(name), expect, name);
  });

  it('should test names', () => {
    const names = [
      ['..', [false, 1]],
      ['@.', [true, 1]],
      ['www.example.com', [true, 3]],
      ['www.e%ample.com', [true, 3]],
      ['www.example.com.', [true, 3]],
      ['mi\\k.nl.', [true, 2]],
      ['mi\\k.nl', [true, 2]]
    ];

    for (const [name, expect] of names) {
      assert.strictEqual(util.isName(name), expect[0]);

      if (expect[0]) {
        const [, labels] = encoding.writeName(
          null,
          util.fqdn(name),
          0,
          null,
          false
        );
        assert.strictEqual(labels, expect[1]);
      }
    }
  });

  it('should test subdomains', () => {
    const yes = [
      ['miek1.nl', 'miek1.nl'],
      ['miek.nl', 'ns.miek.nl'],
      ['.', 'miek.nl']
    ];

    for (const [parent, child] of yes)
      assert.strictEqual(util.isSubdomain(parent, child), true);

    const no = [
      ['www.miek.nl', 'ns.miek.nl'],
      ['m\\.iek.nl', 'ns.miek.nl'],
      ['w\\.iek.nl', 'w.iek.nl'],
      ['p\\\\.iek.nl', 'ns.p.iek.nl'], // p\\.iek.nl , literal \ in domain name
      ['miek.nl', '.']
    ];

    for (const [parent, child] of no)
      assert.strictEqual(util.isSubdomain(parent, child), false);
  });

  it('should add origin', () => {
    const tests = [
      ['@', 'example.com', 'example.com'],
      ['foo', 'example.com', 'foo.example.com'],
      ['foo.', 'example.com', 'foo.'],
      ['@', 'example.com.', 'example.com.'],
      ['foo', 'example.com.', 'foo.example.com.'],
      ['foo.', 'example.com.', 'foo.'],
      ['example.com', '.', 'example.com.'],
      ['example.com.', '.', 'example.com.'],
      // Oddball tests:
      // In general origin should not be '' or '.' but at least
      // these tests verify we don't crash and will keep results
      // from changing unexpectedly.
      ['*.', '', '*.'],
      ['@', '', '@'],
      ['foobar', '', 'foobar'],
      ['foobar.', '', 'foobar.'],
      ['*.', '.', '*.'],
      ['@', '.', '.'],
      ['foobar', '.', 'foobar.'],
      ['foobar.', '.', 'foobar.']
    ];

    for (const [e1, e2, expected] of tests) {
      const actual = util.addOrigin(e1, e2);
      assert.strictEqual(actual, expected);
    }
  });

  it('should trim domain names', () => {
    // Basic tests.
    const testsEx = [
      ['foo.example.com', 'foo'],
      ['foo.example.com.', 'foo'],
      ['.foo.example.com', '.foo'],
      ['.foo.example.com.', '.foo'],
      ['*.example.com', '*'],
      ['example.com', '@'],
      ['example.com.', '@'],
      ['com.', 'com.'],
      ['foo.', 'foo.'],
      ['serverfault.com.', 'serverfault.com.'],
      ['serverfault.com', 'serverfault.com'],
      ['.foo.ronco.com', '.foo.ronco.com'],
      ['.foo.ronco.com.', '.foo.ronco.com.']
    ];

    for (const dom of ['example.com', 'example.com.']) {
      for (const [experiment, expected] of testsEx) {
        const actual = util.trimDomainName(experiment, dom);
        assert.strictEqual(actual, expected, experiment);
      }
    }

    // Paranoid tests.
    const tests = [
      ['', '@'],
      ['.', '.'],
      ['a.b.c.d.e.f.', 'a.b.c.d.e'],
      ['b.c.d.e.f.', 'b.c.d.e'],
      ['c.d.e.f.', 'c.d.e'],
      ['d.e.f.', 'd.e'],
      ['e.f.', 'e'],
      ['f.', '@'],
      ['.a.b.c.d.e.f.', '.a.b.c.d.e'],
      ['.b.c.d.e.f.', '.b.c.d.e'],
      ['.c.d.e.f.', '.c.d.e'],
      ['.d.e.f.', '.d.e'],
      ['.e.f.', '.e'],
      ['.f.', '@'],
      ['a.b.c.d.e.f', 'a.b.c.d.e'],
      ['a.b.c.d.e.', 'a.b.c.d.e.'],
      ['a.b.c.d.e', 'a.b.c.d.e'],
      ['a.b.c.d.', 'a.b.c.d.'],
      ['a.b.c.d', 'a.b.c.d'],
      ['a.b.c.', 'a.b.c.'],
      ['a.b.c', 'a.b.c'],
      ['a.b.', 'a.b.'],
      ['a.b', 'a.b'],
      ['a.', 'a.'],
      ['a', 'a'],
      ['.a.b.c.d.e.f', '.a.b.c.d.e'],
      ['.a.b.c.d.e.', '.a.b.c.d.e.'],
      ['.a.b.c.d.e', '.a.b.c.d.e'],
      ['.a.b.c.d.', '.a.b.c.d.'],
      ['.a.b.c.d', '.a.b.c.d'],
      ['.a.b.c.', '.a.b.c.'],
      ['.a.b.c', '.a.b.c'],
      ['.a.b.', '.a.b.'],
      ['.a.b', '.a.b'],
      ['.a.', '.a.'],
      ['.a', '.a']
    ];

    for (const dom of ['f', 'f.']) {
      for (const [experiment, expected] of tests) {
        const actual = util.trimDomainName(experiment, dom);
        assert.strictEqual(actual, expected, experiment);
      }
    }

    // Test cases for bugs found in the wild.
    const testsWild = [
      ['mathoverflow.net.', '.', 'mathoverflow.net'],
      ['mathoverflow.net', '.', 'mathoverflow.net'],
      ['', '.', '@'],
      ['@', '.', '@']
    ];

    for (const [e1, e2, expected] of testsWild) {
      const actual = util.trimDomainName(e1, e2);
      assert.strictEqual(actual, expected, e1);
    }
  });

  it('should test isFQDN', () => {
    const vectors = [
      ['.', true],
      ['\\.', false],
      ['\\\\.', true],
      ['\\\\\\.', false],
      ['\\\\\\\\.', true],
      ['a.', true],
      ['a\\.', false],
      ['a\\\\.', true],
      ['a\\\\\\.', false],
      ['ab.', true],
      ['ab\\.', false],
      ['ab\\\\.', true],
      ['ab\\\\\\.', false],
      ['..', true],
      ['.\\.', false],
      ['.\\\\.', true],
      ['.\\\\\\.', false],
      ['example.org.', true],
      ['example.org\\.', false],
      ['example.org\\\\.', true],
      ['example.org\\\\\\.', false],
      ['example\\.org.', true],
      ['example\\\\.org.', true],
      ['example\\\\\\.org.', true],
      ['\\example.org.', true],
      ['\\\\example.org.', true],
      ['\\\\\\example.org.', true]
    ];

    for (const [s, expect] of vectors)
      assert.strictEqual(util.isFQDN(s), expect);
  });
});
