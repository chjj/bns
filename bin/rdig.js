#!/usr/bin/env node

'use strict';

const pkg = require('../package.json');
const rdns = require('../lib/rdns');
const util = require('../lib/util');

let name = null;
let type = null;
let host = null;
let port = 53;
let inet6 = null;
let reverse = false;
let json = false;
let rd = false;
let edns = false;
let dnssec = false;
let debug = false;

for (let i = 2; i < process.argv.length; i++) {
  const arg = process.argv[i];

  if (arg.length === 0)
    throw new Error(`Unexpected argument: ${arg}.`);

  switch (arg) {
    case '-4':
      inet6 = false;
      break;
    case '-6':
      inet6 = true;
      break;
    case '-x':
      reverse = true;
      break;
    case '-p':
      port = util.parseU16(process.argv[i + 1]);
      i += 1;
      break;
    case '-j':
      json = true;
      break;
    case '-q':
      name = arg;
      break;
    case '-t':
      type = arg;
      break;
    case '-h':
    case '--help':
    case '-?':
    case '-v':
      console.log(`rdig.js ${pkg.version}`);
      process.exit(0);
      break;
    case '+edns':
      edns = true;
      break;
    case '+noedns':
      edns = false;
      break;
    case '+dnssec':
      edns = true;
      dnssec = true;
      break;
    case '+nodnssec':
      dnssec = false;
      break;
    case '+rd':
      rd = true;
      break;
    case '+nord':
      rd = false;
      break;
    case '+debug':
      debug = true;
      break;
    case '+nodebug':
      debug = false;
      break;
    default:
      if (arg[0] === '@') {
        host = arg.substring(1);
        break;
      }

      if (!name) {
        name = arg;
        break;
      }

      if (!type) {
        type = arg;
        break;
      }

      throw new Error(`Unexpected argument: ${arg}.`);
  }
}

if (!name)
  name = '.';

if (!type)
  type = 'A';

async function resolve(name, type, options) {
  const resolver = new rdns.Resolver(options);

  if (options.debug) {
    resolver.on('error', (err) => {
      console.error(err.stack);
    });

    resolver.on('log', (...args) => {
      console.error(...args);
    });
  }

  if (options.reverse)
    return resolver.reverseRaw(name);

  return resolver.resolveRaw(name, type);
}

function printHeader(host) {
  const argv = process.argv.slice(2).join(' ');
  process.stdout.write('\n');
  process.stdout.write(`; <<>> rdig.js ${pkg.version} <<>> ${argv}\n`);
  if (host)
    process.stdout.write('; (1 server found)\n');
  process.stdout.write(';; global options: +cmd\n');
}

(async () => {
  const now = Date.now();

  const res = await resolve(name, type, {
    host,
    port,
    inet6,
    reverse,
    rd,
    edns,
    dnssec,
    debug
  });

  const ms = Date.now() - now;

  if (json) {
    const text = JSON.stringify(res.toJSON(), null, 2);
    process.stdout.write(text + '\n');
  } else {
    printHeader(host);
    process.stdout.write(';; Got answer:\n');
    process.stdout.write(res.toString(ms) + '\n');
  }
})().catch((err) => {
  if (json) {
    console.error(err.message);
    process.exit(1);
  } else {
    printHeader(host);
    process.stdout.write(`;; error; ${err.message}\n`);
  }
});
