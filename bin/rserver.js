#!/usr/bin/env node

'use strict';

const {RecursiveServer} = require('../lib/server');
const server = new RecursiveServer('udp4');
const util = require('../lib/util');

server.on('error', (err) => {
  console.error(err.stack);
});

server.on('log', (...args) => {
  console.error(...args);
});

server.on('query', (req, res, rinfo) => {
  console.log('Rinfo:');
  util.dir(rinfo);
  console.log('Request:');
  util.dir(req);
  console.log('Response:');
  util.dir(res);
});

server.on('listening', () => {
  const {address, port} = server.address();
  console.log(`Server listening on ${address}:${port}.`);
});

// $ dig @127.0.0.1 google.com A -p 5300
// $ node bin/dig.js google.com A 127.0.0.1 5300
// $ dig @::1 -p 5300 mail.google.com AAAA +dnssec +crypto
//server.open(5300, '::');
server.open(53, '127.0.0.1');
