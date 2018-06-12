#!/usr/bin/env node

'use strict';

process.title = 'dig.js';

const IP = require('binet');
const pkg = require('../package.json');
const constants = require('../lib/constants');
const encoding = require('../lib/encoding');
const Hosts = require('../lib/hosts');
const ResolvConf = require('../lib/resolvconf');
const Hints = require('../lib/hints');
const util = require('../lib/util');
const {isTypeString} = constants;

let name = null;
let type = null;
let host = null;
let port = 53;
let conf = null;
let hosts = null;
let recursive = false;
let unbound = false;
let hints = null;
let anchors = null;
let inet6 = null;
let reverse = false;
let json = false;
let rd = true;
let tcp = true;
let edns = true;
let dnssec = false;
let short = false;
let debug = false;
let emailBits = 256;

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
    case '-x':
      reverse = true;
      break;
    case '-p':
      port = util.parseU16(process.argv[i + 1]);
      i += 1;
      break;
    case '-j':
      json = true;
      break;
    case '-q':
      name = arg;
      break;
    case '-t':
      type = arg;
      break;
    case '-b':
      emailBits = util.parseU16(process.argv[i + 1]);
      i += 1;
      break;
    case '--conf':
      conf = ResolvConf.fromFile(process.argv[i + 1]);
      i += 1;
      break;
    case '--hosts':
      hosts = Hosts.fromFile(process.argv[i + 1]);
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
    case '--hints':
      hints = Hints.fromFile(process.argv[i + 1]);
      i += 1;
      break;
    case '--anchor':
      if (process.argv[i + 1]) {
        if (!anchors)
          anchors = [];
        anchors.push(process.argv[i + 1]);
      }
      i += 1;
      break;
    case '-h':
    case '--help':
    case '-?':
    case '-v':
      console.log(`dig.js ${pkg.version}`);
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
    case '+rd':
      rd = true;
      break;
    case '+nord':
      rd = false;
      break;
    case '+json':
      json = true;
      break;
    case '+nojson':
      json = false;
      break;
    case '+short':
      short = true;
      break;
    case '+noshort':
      short = false;
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

      if (!type && isTypeString(arg)) {
        type = arg;
        break;
      }

      if (!name) {
        name = arg;
        break;
      }

      throw new Error(`Unexpected argument: ${arg}.`);
  }
}

if (!name)
  name = '.';

if (!type)
  type = 'A';

if (type === 'SMIMEA' && name.indexOf('@') !== -1) {
  const smimea = require('../lib/smimea');
  try {
    name = smimea.encodeEmail(name, emailBits);
  } catch (e) {
    ;
  }
}

if (type === 'OPENPGPKEY' && name.indexOf('@') !== -1) {
  const openpgpkey = require('../lib/openpgpkey');
  try {
    name = openpgpkey.encodeEmail(name, emailBits);
  } catch (e) {
    ;
  }
}

async function lookup(name) {
  const dns = require('../lib/dns');
  const options = { all: true, hints: dns.ADDRCONFIG };
  const addrs = await dns.lookup(host, options);

  if (recursive) {
    const inet4 = addrs.filter(addr => addr.family === 4);
    const {address} = util.randomItem(inet4);
    return address;
  }

  const {address} = util.randomItem(addrs);
  return address;
}

async function resolve(name, type, options) {
  let dns;

  if (unbound)
    dns = require('../lib/udns');
  else if (recursive)
    dns = require('../lib/rdns');
  else
    dns = require('../lib/dns');

  const resolver = new dns.Resolver(options);

  if (options.debug) {
    resolver.on('error', (err) => {
      console.error(err.stack);
    });

    resolver.on('log', (...args) => {
      console.error(...args);
    });
  }

  if (!recursive) {
    const {host, port} = options;
    if (host) {
      const server = IP.toHost(host, port);
      resolver.setServers([server]);
    }
  }

  return resolver.resolveRaw(name, type);
}

function printHeader(host) {
  const argv = process.argv.slice(2).join(' ');
  process.stdout.write('\n');
  process.stdout.write(`; <<>> dig.js ${pkg.version} <<>> ${argv}\n`);
  if (host)
    process.stdout.write('; (1 server found)\n');
  process.stdout.write(';; global options: +cmd\n');
}

(async () => {
  if (recursive) {
    let ns = 'hints.local.';

    if (host && !util.isIP(host)) {
      ns = host;
      host = await lookup(host);
    }

    if (host && !hints) {
      hints = new Hints();
      hints.addServer(ns, host);
      if (anchors) {
        for (const ds of anchors)
          hints.addAnchor(ds);
      }
    }

    if (hints)
      hints.port = port;
  } else {
    if (host && !util.isIP(host))
      host = await lookup(host);
  }

  if (reverse) {
    name = encoding.reverse(name);
    type = 'PTR';
  }

  const now = Date.now();

  const res = await resolve(name, type, {
    hints,
    host,
    port,
    conf,
    hosts,
    inet6,
    rd,
    tcp,
    edns,
    dnssec,
    debug
  });

  if (recursive) {
    res.rd = rd;
    if (edns && !res.isEDNS())
      res.setEDNS(4096, dnssec);
  }

  if (json) {
    const text = JSON.stringify(res.toJSON(), null, 2);
    process.stdout.write(text + '\n');
  } else {
    if (short) {
      process.stdout.write(res.toShort(name, type));
    } else {
      if (res.malformed) {
        process.stdout.write(';; Warning:');
        process.stdout.write(' Message parser reports');
        process.stdout.write(' malformed message packet.\n\n');
      }

      printHeader(host);

      process.stdout.write(';; Got answer:\n');

      // Note: should go after header flags.
      if (rd && !res.ra) {
        process.stdout.write(';; WARNING:');
        process.stdout.write(' recursion requested but not available\n');
      }

      process.stdout.write(res.toString(now, host, port) + '\n');
    }
  }
})().catch((err) => {
  if (debug)
    process.stderr.write(err.stack + '\n');

  if (json) {
    process.stderr.write(err.message + '\n');
    process.exit(1);
  } else {
    if (short) {
      process.stderr.write(err.message + '\n');
    } else {
      printHeader(host);
      process.stdout.write(`;; error; ${err.message}\n`);
    }
  }
});
