#!/usr/bin/env node

'use strict';

const {RecursiveResolver} = require('../lib/resolver');
const wire = require('../lib/wire');
const reverse = process.argv.indexOf('-x');

if (reverse !== -1)
  process.argv.splice(reverse, 1);

const {
  Message,
  Question,
  types,
  classes,
  opcodes
} = wire;

function log(obj) {
  console.dir(obj, {
    depth: 20,
    customInspect: true,
    colors: true
  });
}

async function resolve(name, type, host, port) {
  const resolver = new RecursiveResolver('udp4');

  await resolver.open();

  let auth = null;

  if (host != null) {
    auth = {
      name: '.',
      host: host,
      port: port || 53,
      zone: '.'
    };
  }

  if (reverse !== -1) {
    try {
      return await resolver.reverse(name, auth);
    } finally {
      await resolver.close();
    }
  }

  try {
    return await resolver.lookup(name, type, auth);
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
