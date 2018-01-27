#!/usr/bin/env node

'use strict';

const assert = require('assert');
const DNSResolver = require('../lib/resolver');
const wire = require('../lib/wire');

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
  if (name == null)
    name = '.';

  if (type == null)
    type = 'ANY';

  if (typeof type === 'string')
    type = types[type] || types.ANY;

  if (host == null)
    host = '208.67.222.222';

  if (port == null)
    port = 53;

  if (name[name.length - 1] !== '.')
    name += '.';

  const resolver = new DNSResolver('udp4');

  await resolver.open();

  const req = new Message();
  req.opcode = opcodes.QUERY;

  const q = new Question();
  q.name = name;
  q.type = type;
  q.class = classes.INET;

  req.question.push(q);

  try {
    return await resolver.resolve(req, port, host);
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
