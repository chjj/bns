#!/usr/bin/env node

'use strict';

const DNSServer = require('../lib/server/dns');
const wire = require('../lib/wire');
const util = require('../lib/util');

const {
  Record,
  ARecord,
  AAAARecord,
  types,
  classes,
  opcodes
} = wire;

const server = new DNSServer({
  inet6: null,
  edns: true,
  dnssec: true
});

server.on('error', (err) => {
  console.error(err.stack);
});

server.on('log', (...args) => {
  console.error(...args);
});

server.on('query', (req, res, rinfo) => {
  if (req.opcode !== opcodes.QUERY)
    return;

  if (req.question.length === 0)
    return;

  for (const qs of req.question) {
    if (qs.class !== classes.IN
        && qs.class !== classes.ANY) {
      continue;
    }

    const answer = new Record();
    answer.name = qs.name;
    answer.class = classes.IN;

    if (qs.type === types.A || qs.type === types.ANY) {
      answer.type = types.A;
      answer.data = new ARecord();
    } else if (qs.type === types.AAAA) {
      answer.type = types.AAAA;
      answer.data = new AAAARecord();
    } else {
      continue;
    }

    res.answer.push(answer);
  }

  console.log('Rinfo:');
  util.dir(rinfo);
  console.log('Request:');
  util.dir(req);
  console.log('Response:');
  util.dir(res);

  res.send();
});

server.on('listening', () => {
  const {address, port} = server.address();
  console.log(`Server listening on ${address}:${port}.`);
});

server.open(5300, '127.0.0.1');
