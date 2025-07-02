'use strict';

const rc = require('bslintrc');

module.exports = [
  rc.configs.recommended,
  rc.configs.bcoin,
  {
    languageOptions: {
      globals: {
        ...rc.globals.node
      },
      ecmaVersion: 'latest'
    }
  },
  {
    files: [
      'bin/bns-keygen',
      'bin/bns-prove',
      'bin/dig.js',
      'bin/dig2json',
      'bin/json2dig',
      'bin/json2rr',
      'bin/json2zone',
      'bin/named.js',
      'bin/read.js',
      'bin/rr2json',
      'bin/whois.js',
      'bin/zone2json',
      '**/*.js',
      '*.js'
    ],
    languageOptions: {
      sourceType: 'commonjs'
    }
  },
  {
    files: ['test/{,**/}*.{js,cjs,mjs}'],
    languageOptions: {
      globals: {
        ...rc.globals.mocha,
        register: 'readable'
      }
    },
    rules: {
      'max-len': 'off',
      'prefer-arrow-callback': 'off'
    }
  }
];
