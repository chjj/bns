#!/usr/bin/env node

'use strict';

process.title = 'whois.js';

const tcp = require('btcp');
const dns = require('../lib/dns');
const encoding = require('../lib/encoding');
const util = require('../lib/util');
const whois = require('../etc/whois.json');

function getServer(name) {
  const labels = util.split(name);

  if (labels.length === 0)
    return null;

  if (labels.length === 1)
    return whois['.'];

  const sld = util.from(name, labels, -2);
  const tld = util.from(name, labels, -1);
  const server = whois[sld] || whois[tld];

  if (typeof server !== 'string')
    return null;

  return server;
}

let name = null;
let server = null;

for (let i = 2; i < process.argv.length; i++) {
  const arg = process.argv[i];

  if (arg.length === 0)
    throw new Error('Unexpected argument.');

  switch (arg) {
    default:
      if (arg[0] === '@') {
        server = arg.substring(1);
        break;
      }

      if (!name) {
        name = util.fqdn(arg.toLowerCase());
        break;
      }

      throw new Error(`Unexpected argument: ${arg}.`);
  }
}

if (!name) {
  console.error('No name provided.');
  process.exit(1);
  return;
}

if (!encoding.isName(name)) {
  console.error(`Invalid domain name: ${name}.`);
  process.exit(1);
  return;
}

if (!server)
  server = getServer(name);

if (!server) {
  console.error(`WHOIS server not found for: ${name}.`);
  process.exit(1);
  return;
}

(async () => {
  console.error(`WHOIS ${name} (${server})`);

  if (!util.isIP(server)) {
    const options = { all: true, hints: dns.ADDRCONFIG };
    const addrs = await dns.lookup(server, options);
    const inet4 = addrs.filter(addr => addr.family === 4);
    const {address} = util.randomItem(inet4);

    server = address;
  }

  console.error(`Connecting to ${server}.`);
  console.error('');

  const socket = new tcp.Socket();

  socket.on('error', (err) => {
    console.error(err.message);
    process.exit(1);
  });

  socket.once('connect', () => {
    socket.write(util.trimFQDN(name) + '\r\n');
  });

  socket.setEncoding('utf8');
  socket.pipe(process.stdout);
  socket.connect(43, server);
})().catch((err) => {
  console.error(err.stack);
  process.exit(1);
});
