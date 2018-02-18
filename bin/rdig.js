#!/usr/bin/env node

'use strict';

const {RecursiveResolver} = require('../lib/resolver');
const IP = require('binet');
const wire = require('../lib/wire');
const reverse = process.argv.indexOf('-x');

if (reverse !== -1)
  process.argv.splice(reverse, 1);

const {
  Message,
  Question,
  Record,
  types,
  classes,
  opcodes
} = wire;

function log(obj) {
  // console.dir(obj, {
  //   depth: 20,
  //   customInspect: true,
  //   colors: true
  // });
  console.log(obj.toString());
}

async function resolve(name, type, host, port) {
  const resolver = new RecursiveResolver('udp4');

  resolver.on('log', (...args) => {
    console.error(...args);
  });

  await resolver.open();

  if (host != null) {
    const ip = IP.normalize(host);

    resolver.hints.reset();
    resolver.hints.ns.push('hints.local.');

    if (IP.isIPv4String(ip))
      resolver.hints.inet4.set('hints.local.', ip);
    else
      resolver.hints.inet6.set('hints.local.', ip);

    if (port != null)
      resolver.hints.port = port;

    const anchor = '. 172800 IN DS 28834 8 2 305fadd310e0e468faa92d65d3d0c0fe1ff740f86f2b203bd46986bdf25582d5';
    resolver.hints.anchors.push(Record.fromString(anchor));
  }

  if (reverse !== -1) {
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
  const name = process.argv[2] || null;
  const type = process.argv[3] || null;
  const host = process.argv[4] || null;
  const port = (process.argv[5] | 0) || null;
  log(await resolve(name, type, host, port));
})();
