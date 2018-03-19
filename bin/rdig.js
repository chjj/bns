#!/usr/bin/env node

'use strict';

const pkg = require('../package.json');
const {RecursiveResolver} = require('../lib/resolver');
const util = require('../lib/util');

let name = null;
let type = null;
let host = null;
let port = null;
let inet6 = false;
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
      console.log(`bns ${pkg.version}`);
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
  const resolver = new RecursiveResolver(options.inet6 ? 'udp6' : 'udp4');

  resolver.rd = Boolean(options.rd);
  resolver.edns = Boolean(options.edns);
  resolver.dnssec = Boolean(options.dnssec);

  if (options.debug) {
    resolver.on('log', (...args) => {
      console.error(...args);
    });
  }

  await resolver.open();

  if (options.reverse) {
    try {
      return await resolver.reverse(name);
    } finally {
      await resolver.close();
    }
  }

  try {
    return await resolver.lookup(name, type);
  } finally {
    await resolver.close();
  }
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
    const argv = process.argv.slice(2).join(' ');
    process.stdout.write('\n');
    process.stdout.write(`; <<>> bns ${pkg.version} <<>> ${argv}\n`);
    process.stdout.write(';; Got answer:\n');
    process.stdout.write(res.toString(ms) + '\n');
  }
})().catch((err) => {
  console.error(err.message);
  process.exit(1);
});
