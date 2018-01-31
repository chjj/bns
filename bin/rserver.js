#!/usr/bin/env node

'use strict';

const {RecursiveServer} = require('../lib/server');
const server = new RecursiveServer('udp4');

server.on('error', (err) => {
  console.error(err.stack);
  server.close();
});

server.on('listening', () => {
  const {address, port} = server.address();
  console.log(`Server listening on ${address}:${port}.`);
});

// $ dig @127.0.0.1 google.com A -p 5300
// $ node bin/dig.js google.com A 127.0.0.1 5300
server.open(5300);
