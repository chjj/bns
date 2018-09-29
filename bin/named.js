#!/usr/bin/env node

'use strict';

process.title = 'named.js';

const pkg = require('../package.json');
const AuthServer = require('../lib/server/auth');
const RecursiveServer = require('../lib/server/recursive');
const UnboundServer = require('../lib/server/unbound');
const StubServer = require('../lib/server/stub');
const util = require('../lib/util');

let host = '127.0.0.1';
let port = 53;
let confFile = null;
let hostsFile = null;
let recursive = false;
let unbound = false;
let minimize = false;
let hintsFile = null;
let origin = '.';
let zoneFile = null;
let inet6 = null;
let tcp = true;
let edns = true;
let dnssec = false;
let debug = false;

for (let i = 2; i < process.argv.length; i++) {
  const arg = process.argv[i];

  if (arg.length === 0)
    throw new Error('Unexpected argument.');

  switch (arg) {
    case '-4':
      inet6 = false;
      break;
    case '-6':
      inet6 = true;
      break;
    case '-p':
      port = util.parseU16(process.argv[i + 1]);
      i += 1;
      break;
    case '--conf':
      confFile = process.argv[i + 1];
      i += 1;
      break;
    case '--hosts':
      hostsFile = process.argv[i + 1];
      i += 1;
      break;
    case '-r':
    case '--recursive':
      recursive = true;
      break;
    case '-u':
    case '--unbound':
      unbound = true;
      recursive = true;
      break;
    case '-m':
    case '--minimize':
      minimize = true;
      break;
    case '--hints':
      hintsFile = process.argv[i + 1];
      i += 1;
      break;
    case '-o':
    case '--origin':
      origin = process.argv[i + 1];
      i += 1;
      break;
    case '-z':
    case '--zone':
      zoneFile = process.argv[i + 1];
      i += 1;
      break;
    case '-h':
    case '--help':
    case '-?':
    case '-v':
      console.log(`named.js ${pkg.version}`);
      process.exit(0);
      break;
    case '+vc':
    case '+tcp':
      tcp = true;
      break;
    case '+novc':
    case '+notcp':
      tcp = false;
      break;
    case '+edns':
      edns = true;
      break;
    case '+noedns':
      edns = false;
      break;
    case '+dnssec':
      edns = true;
      dnssec = true;
      break;
    case '+nodnssec':
      dnssec = false;
      break;
    case '+debug':
      debug = true;
      break;
    case '+nodebug':
      debug = false;
      break;
    default:
      if (arg[0] === '@') {
        host = arg.substring(1);
        break;
      }

      if (zoneFile) {
        origin = arg;
        break;
      }

      throw new Error(`Unexpected argument: ${arg}.`);
  }
}

let Server;

if (zoneFile)
  Server = AuthServer;
else if (unbound)
  Server = UnboundServer;
else if (recursive)
  Server = RecursiveServer;
else
  Server = StubServer;

const server = new Server({
  inet6,
  tcp,
  edns,
  dnssec,
  minimize
});

if (zoneFile) {
  server.setOrigin(origin);
  server.setFile(zoneFile);
} else if (recursive) {
  if (hintsFile)
    server.hints.fromFile(hintsFile);
  else
    server.hints.fromRoot();
} else {
  if (confFile)
    server.conf.fromFile(confFile);
  else
    server.conf.fromSystem();

  if (hostsFile)
    server.hosts.fromFile(hostsFile);
  else
    server.hosts.fromSystem();
}

server.on('error', (err) => {
  console.error(err.stack);
});

if (debug) {
  server.on('log', (...args) => {
    console.error(...args);
  });

  server.on('query', (req, res, rinfo) => {
    console.error('');
    console.error('Rinfo:');
    console.error('Address: %s, Port: %d, TCP: %s',
      rinfo.address, rinfo.port, rinfo.tcp);

    console.error('');
    console.error('Request:');
    console.error(req.toString());

    console.error('Response:');
    console.error(res.toString());
  });
}

server.on('listening', () => {
  const {address, port} = server.address();
  console.log(`Server listening on ${address}:${port}.`);
});

server.open(port, host);
