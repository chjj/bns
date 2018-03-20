#!/usr/bin/env node

'use strict';

const {RecursiveServer} = require('../lib/server');
const server = new RecursiveServer();

server.on('error', (err) => {
  console.error(err.stack);
});

server.on('log', (...args) => {
  console.error(...args);
});

server.on('query', (req, res, rinfo) => {
  console.log('');
  console.log('Rinfo:');
  console.log('Address: %s, Port: %d, TCP: %s',
    rinfo.address, rinfo.port, rinfo.tcp);

  console.log('');
  console.log('Request:');
  console.log(req.toString());

  console.log('');
  console.log('Response:');
  console.log(res.toString());
  console.log('');
});

server.on('listening', () => {
  const {address, port} = server.address();
  console.log(`Server listening on ${address}:${port}.`);
});

server.open(53, '127.0.0.1');
