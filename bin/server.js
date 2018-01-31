#!/usr/bin/env node

'use strict';

const {DNSServer} = require('../lib/server');
const wire = require('../lib/wire');

const {
  Message,
  Question,
  Record,
  ARecord,
  AAAARecord,
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

const server = new DNSServer('udp4');

server.on('error', (err) => {
  console.error(err.stack);
  server.close();
});

server.on('query', (req, res) => {
  if (req.opcode !== opcodes.QUERY)
    return;

  if (req.question.length === 0)
    return;

  console.log('Received request:');
  log(req);

  for (const qs of req.question) {
    if (qs.class !== classes.INET
        && qs.class !== classes.ANY) {
      continue;
    }

    const answer = new Record();
    answer.name = qs.name;
    answer.class = classes.INET;

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

  res.send();
});

server.on('listening', () => {
  const {address, port} = server.address();
  console.log(`Server listening on ${address}:${port}.`);
});

// $ dig @127.0.0.1 google.com A -p 5300
// $ node bin/dig.js google.com A 127.0.0.1 5300
server.open(5300);
