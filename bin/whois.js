#!/usr/bin/env node

'use strict';

const tcp = require('btcp');
const dns = require('../lib/dns');
const encoding = require('../lib/encoding');
const util = require('../lib/util');
const whois = require('../hints/whois.json');

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

(async () => {
  if (process.argv.length < 3) {
    console.error('No name provided.');
    process.exit(1);
    return;
  }

  const arg = process.argv[2].toLowerCase();
  const name = util.fqdn(arg);

  if (!encoding.isName(name)) {
    console.error(`Invalid domain name: ${name}.`);
    process.exit(1);
    return;
  }

  const server = getServer(name);

  if (!server) {
    console.error(`WHOIS server not found for: ${name}.`);
    process.exit(1);
    return;
  }

  console.error(`WHOIS ${name} (${server})`);

  const inet4 = await dns.resolve4(server);
  const host = util.randomItem(inet4);

  console.error(`Connecting to ${host}.`);
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
  socket.connect(43, host);
})().catch((err) => {
  console.error(err.stack);
  process.exit(1);
});
