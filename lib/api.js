/*!
 * api.js - node.js api for bns
 * Copyright (c) 2018, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bns
 */

'use strict';

const assert = require('assert');
const EventEmitter = require('events');
const IP = require('binet');
const constants = require('./constants');
const encoding = require('./encoding');
const ResolvConf = require('./resolvconf');
const smimea = require('./smimea');
const sshfp = require('./sshfp');
const tlsa = require('./tlsa');
const util = require('./util');
const wire = require('./wire');

const {
  types,
  codes
} = wire;

/*
 * Constants
 */

const hasIPv4 = IP.getInterfaces('ipv4').length > 0;
const hasIPv6 = IP.getInterfaces('ipv6').length > 0;

let conf = null;

/**
 * API
 */

class API extends EventEmitter {
  constructor(create, options) {
    super();

    assert(typeof create === 'function');

    // Private
    this._create = create;
    this._options = options;
    this._resolvers = new Set();
    this._servers = null;
    this._onError = err => this.emit('error', err);
    this._onLog = (...args) => this.emit('log', ...args);

    // Public
    this.Resolver = function Resolver(options) {
      return new API(create, options);
    };

    this.V4MAPPED = 8;
    this.ADDRCONFIG = 32;

    this.NODATA = 'ENODATA';
    this.FORMERR = 'EFORMERR';
    this.SERVFAIL = 'ESERVFAIL';
    this.NOTFOUND = 'ENOTFOUND';
    this.NOTIMP = 'ENOTIMP';
    this.REFUSED = 'EREFUSED';
    this.BADQUERY = 'EBADQUERY';
    this.BADNAME = 'EBADNAME';
    this.BADFAMILY = 'EBADFAMILY';
    this.BADRESP = 'EBADRESP';
    this.CONNREFUSED = 'ECONNREFUSED';
    this.TIMEOUT = 'ETIMEOUT';
    this.EOF = 'EOF';
    this.FILE = 'EFILE';
    this.NOMEM = 'ENOMEM';
    this.DESTRUCTION = 'EDESTRUCTION';
    this.BADSTR = 'EBADSTR';
    this.BADFLAGS = 'EBADFLAGS';
    this.NONAME = 'ENONAME';
    this.BADHINTS = 'EBADHINTS';
    this.NOTINITIALIZED = 'ENOTINITIALIZED';
    this.LOADIPHLPAPI = 'ELOADIPHLPAPI';
    this.ADDRGETNETWORKPARAMS = 'EADDRGETNETWORKPARAMS';
    this.CANCELLED = 'ECANCELLED';

    // Custom
    this.INSECURE = 'EINSECURE';
    this.BADSIGNATURE = 'EBADSIGNATURE';
    this.NORESFLAG = 'ENORESFLAG';
    this.BADQUESTION = 'EBADQUESTION';
    this.BADTRUNCATION = 'EBADTRUNCATION';
    this.BADOPCODE = 'EBADOPCODE';
    this.LAMESERVER = 'ELAMESERVER';
    this.NOAUTHORITY = 'ENOAUTHORITY';
    this.ALIASLOOP = 'EALIASLOOP';

    // Swallow errors
    this.on('error', () => {});
  }

  async _ask(resolver, name, type) {
    await resolver.open();

    this._resolvers.add(resolver);

    let res;
    try {
      res = await resolver.lookup(name, type);
    } catch (e) {
      this._resolvers.delete(resolver);

      await resolver.close();

      switch (e.message) {
        case 'Request timed out.':
          throw makeQueryError(name, type, this.TIMEOUT);
        case 'Request cancelled.':
          throw makeQueryError(name, type, this.CANCELLED);
        case 'Format error.':
          throw makeQueryError(name, type, this.FORMERR);
        // Custom:
        case 'Could not verify response.':
          throw makeQueryError(name, type, this.BADSIGNATURE);
        case 'Not a response.':
          throw makeQueryError(name, type, this.NORESFLAG);
        case 'Invalid question.':
          throw makeQueryError(name, type, this.BADQUESTION);
        case 'Truncated TCP msg.':
          throw makeQueryError(name, type, this.BADTRUNCATION);
        case 'Unexpected opcode.':
          throw makeQueryError(name, type, this.BADOPCODE);
        case 'Server is lame.':
          throw makeQueryError(name, type, this.LAMESERVER);
        case 'Authority lookup failed.':
        case 'No authority address.':
          throw makeQueryError(name, type, this.NOAUTHORITY);
        case 'Alias loop.':
          throw makeQueryError(name, type, this.ALIASLOOP);
      }

      throw e;
    }

    this._resolvers.delete(resolver);

    await resolver.close();

    return res;
  }

  async _query(name, type) {
    assert(typeof name === 'string');
    assert((type & 0xffff) === type);

    const resolver = await this._create(this._options, this._servers);

    resolver.on('error', this._onError);
    resolver.on('log', this._onLog);

    try {
      return await this._ask(resolver, name, type);
    } finally {
      resolver.removeListener('error', this._onError);
      resolver.removeListener('log', this._onLog);
    }
  }

  async _lookup(name, type, secure, map) {
    assert(typeof secure === 'boolean');
    assert(typeof map === 'function');

    const res = await this._query(name, type);

    if (res.code !== codes.NOERROR) {
      switch (res.code) {
        case codes.FORMERR:
          throw makeQueryError(name, type, this.FORMERR);
        case codes.SERVFAIL:
          throw makeQueryError(name, type, this.SERVFAIL);
        case codes.NXDOMAIN:
          throw makeQueryError(name, type, this.NOTFOUND);
        case codes.NOTIMP:
          throw makeQueryError(name, type, this.NOTIMP);
        case codes.REFUSED:
          throw makeQueryError(name, type, this.REFUSED);
      }
      throw makeQueryError(name, type, this.BADRESP);
    }

    if (secure && !res.ad)
      throw makeQueryError(name, type, this.INSECURE);

    const answer = res.collect(name, type);

    if (answer.length === 0)
      throw makeQueryError(name, type, this.NODATA);

    const result = [];

    for (const rr of answer) {
      const obj = map(rr);
      if (obj)
        result.push(obj);
    }

    return result;
  }

  async _resolve(name, type, map) {
    return this._lookup(name, type, false, map);
  }

  async _resolveSecure(name, type, map) {
    return this._lookup(name, type, true, map);
  }

  getServers() {
    if (!this._servers) {
      if (!conf)
        conf = ResolvConf.fromSystem();
      return conf.getServers();
    }
    return this._servers.slice();
  }

  setServers(servers) {
    assert(Array.isArray(servers));

    for (const server of servers) {
      const {type} = IP.fromHost(server, 53);
      switch (type) {
        case 4:
          break;
        case 6:
          break;
        default:
          throw new Error('Invalid address.');
      }
    }

    this._servers = servers.slice();

    return this;
  }

  async resolve(name, type = 'A') {
    assert(typeof name === 'string');
    assert(typeof type === 'string');

    switch (type) {
      case 'A':
        return this.resolve4(name);
      case 'AAAA':
        return this.resolve6(name);
      case 'CNAME':
        return this.resolveCname(name);
      case 'MX':
        return this.resolveMx(name);
      case 'NAPTR':
        return this.resolveNaptr(name);
      case 'NS':
        return this.resolveNs(name);
      case 'PTR':
        return this.resolvePtr(name);
      case 'SOA':
        return this.resolveSoa(name);
      case 'SRV':
        return this.resolveSrv(name);
      case 'TXT':
        return this.resolveTxt(name);
      case 'ANY':
        return this.resolveAny(name);
      default:
        throw new Error(`Unknown type: ${type}.`);
    }
  }

  async resolve4(name, options = {}) {
    assert(options && typeof options === 'object');

    return this._resolve(name, types.A, (rr) => {
      const {ttl} = rr;
      const {address} = rr.data;

      if (options.ttl)
        return { address, ttl };

      return address;
    });
  }

  async resolve6(name, options = {}) {
    assert(options && typeof options === 'object');

    return this._resolve(name, types.AAAA, (rr) => {
      const {ttl} = rr;
      const {address} = rr.data;

      if (options.ttl)
        return { address, ttl };

      return address;
    });
  }

  async resolveCname(name) {
    return this._resolve(name, types.CNAME, (rr) => {
      return util.trimFQDN(rr.data.target);
    });
  }

  async resolveMx(name) {
    return this._resolve(name, types.MX, (rr) => {
      const rd = rr.data;
      return {
        priority: rd.preference,
        exchange: util.trimFQDN(rd.mx)
      };
    });
  }

  async resolveNaptr(name) {
    return this._resolve(name, types.NAPTR, (rr) => {
      const rd = rr.data;
      return {
        flags: rd.flags,
        service: rd.service,
        regexp: rd.regexp,
        replacement: rd.replacement,
        order: rd.order,
        preference: rd.preference
      };
    });
  }

  async resolveNs(name) {
    return this._resolve(name, types.NS, (rr) => {
      return util.trimFQDN(rr.data.ns);
    });
  }

  async resolvePtr(name) {
    return this._resolve(name, types.PTR, (rr) => {
      return util.trimFQDN(rr.data.ptr);
    });
  }

  async resolveSoa(name) {
    return this._resolve(name, types.SOA, (rr) => {
      const rd = rr.data;
      return {
        nsname: util.trimFQDN(rd.ns),
        hostmaster: util.trimFQDN(rd.mbox),
        serial: rd.serial,
        refresh: rd.refresh,
        retry: rd.retry,
        expire: rd.expire,
        minttl: rd.minttl
      };
    });
  }

  async resolveSrv(name) {
    return this._resolve(name, types.SRV, (rr) => {
      const rd = rr.data;
      return {
        priority: rd.priority,
        weight: rd.weight,
        port: rd.port,
        name: util.trimFQDN(rd.target)
      };
    });
  }

  async resolveTxt(name) {
    return this._resolve(name, types.TXT, (rr) => {
      const rd = rr.data;
      return rd.txt.slice();
    });
  }

  async resolveAny(name) {
    return this._resolve(name, types.ANY, (rr) => {
      const rd = rr.data;

      switch (rr.type) {
        case types.A:
          return {
            type: 'A',
            address: rd.address,
            ttl: rr.ttl
          };
        case types.AAAA:
          return {
            type: 'AAAA',
            address: rd.address,
            ttl: rr.ttl
          };
        case types.CNAME:
          return {
            type: 'CNAME',
            value: util.trimFQDN(rd.target)
          };
        case types.MX:
          return {
            type: 'MX',
            priority: rd.preference,
            exchange: util.trimFQDN(rd.mx)
          };
        case types.NAPTR:
          return {
            type: 'NAPTR',
            flags: rd.flags,
            service: rd.service,
            regexp: rd.regexp,
            replacement: rd.replacement,
            order: rd.order,
            preference: rd.preference
          };
        case types.NS:
          return {
            type: 'NS',
            value: util.trimFQDN(rd.ns)
          };
        case types.PTR:
          return {
            type: 'PTR',
            value: util.trimFQDN(rd.ptr)
          };
        case types.SOA:
          return {
            type: 'SOA',
            nsname: util.trimFQDN(rd.ns),
            hostmaster: util.trimFQDN(rd.mbox),
            serial: rd.serial,
            refresh: rd.refresh,
            retry: rd.retry,
            expire: rd.expire,
            minttl: rd.minttl
          };
        case types.SRV:
          return {
            type: 'SRV',
            priority: rd.priority,
            weight: rd.weight,
            port: rd.port,
            name: util.trimFQDN(rd.target)
          };
        case types.TXT:
          return {
            type: 'TXT',
            entries: rd.txt.slice()
          };
        default:
          return null;
      }
    });
  }

  async reverse(addr) {
    const name = encoding.reverse(addr);
    return this._resolve(name, types.PTR, (rr) => {
      return util.trimFQDN(rr.data.ptr);
    });
  }

  async _lookup4(name, addrs, map) {
    try {
      await this._resolve(name, types.A, (rr) => {
        let address = rr.data.address;
        let family = 4;

        if (map) {
          address = `::ffff:${address}`;
          family = 6;
        }

        addrs.push({ address, family });
      });
    } catch (e) {
      if (e.code !== this.NODATA)
        throw e;
    }
  }

  async _lookup6(name, addrs) {
    try {
      await this._resolve(name, types.AAAA, (rr) => {
        addrs.push({ address: rr.data.address, family: 6 });
      });
    } catch (e) {
      if (e.code !== this.NODATA)
        throw e;
    }
  }

  async lookup(name, options = {}) {
    if (typeof options === 'number')
      options = { family: options };

    assert(name == null || typeof name === 'string');
    assert(options && typeof options === 'object');

    const family = options.family >>> 0;
    const hints = options.hints >>> 0;
    const all = options.all === true;
    const verbatim = options.verbatim === true;

    verbatim;

    assert(family === 0 || family === 4 || family === 6);

    assert(hints === 0
      || hints === this.ADDRCONFIG
      || hints === this.V4MAPPED
      || hints === (this.ADDRCONFIG | this.V4MAPPED));

    if (!name) {
      if (all)
        return [];
      return { address: null, family: family === 6 ? 6 : 4 };
    }

    if (util.isIP(name)) {
      const address = name;
      const ip = IP.toBuffer(address);
      const family = IP.isIPv4(ip) ? 4 : 6;

      if (!all)
        return { address, family };

      return [{ address, family }];
    }

    const addrs = [];

    if (!(hints & this.ADDRCONFIG) || hasIPv4) {
      if (family === 0 || family === 4)
        await this._lookup4(name, addrs, false);
    }

    if (!(hints & this.ADDRCONFIG) || hasIPv6) {
      if (family === 0 || family === 6)
        await this._lookup6(name, addrs);

      if (family === 6 && addrs.length === 0) {
        if (hints & this.V4MAPPED)
          await this._lookup4(name, addrs, true);
      }
    }

    if (addrs.length === 0)
      throw makeGAIError(name, this.NOTFOUND);

    if (!all)
      return addrs[0];

    return addrs;
  }

  async lookupService(addr, port) {
    port = port >>> 0;

    assert(typeof addr === 'string');
    assert((port & 0xffff) === port);

    const name = encoding.reverse(addr);

    const ptrs = await this._resolve(name, types.PTR, (rr) => {
      return util.trimFQDN(rr.data.ptr);
    });

    if (ptrs.length === 0)
      throw makeGNIError(name, this.NOTFOUND);

    return { hostname: ptrs[0], service: null };
  }

  cancel() {
    for (const resolver of this._resolvers)
      resolver.cancel();
  }

  /*
   * Non-standard node.js API
   */

  async resolveRaw(name, type) {
    if (type == null)
      type = types.A;

    if (typeof type === 'string')
      type = constants.stringToType(type);

    return this._query(name, type);
  }

  async reverseRaw(addr) {
    const name = encoding.reverse(addr);
    return this._query(name, types.PTR);
  }

  async resolveTLSA(name, cert, protocol, port) {
    assert(cert == null || Buffer.isBuffer(cert));
    assert(protocol == null || typeof protocol === 'string');
    assert(port == null || (port & 0xffff) === port);

    return this._resolveSecure(name, types.TLSA, (rr) => {
      const rd = rr.data;

      if (cert) {
        if (!tlsa.verify(rr, cert, name, protocol, port))
          return null;
      }

      let decoded;
      try {
        decoded = tlsa.decodeName(rr.name);
      } catch (e) {
        return null;
      }

      return {
        protocol: decoded.protocol,
        port: decoded.port,
        usage: rd.usage,
        certificate: rd.certificate
      };
    });
  }

  async resolveSMIMEA(name, cert, email) {
    assert(cert == null || Buffer.isBuffer(cert));
    assert(email == null || typeof email === 'string');

    return this._resolveSecure(name, types.SMIMEA, (rr) => {
      const rd = rr.data;

      if (cert) {
        if (!smimea.verify(rr, cert, name, email))
          return null;
      }

      let decoded;
      try {
        decoded = smimea.decodeName(rr.name);
      } catch (e) {
        return null;
      }

      return {
        hash: decoded.hash,
        usage: rd.usage,
        certificate: rd.certificate
      };
    });
  }

  async resolveSSHFP(name, key) {
    assert(key == null || Buffer.isBuffer(key));

    return this._resolveSecure(name, types.SSHFP, (rr) => {
      const rd = rr.data;

      if (key) {
        if (!sshfp.verify(rr, key))
          return null;
      }

      return {
        algorithm: rd.algorithm,
        digestType: rd.digestType,
        fingerprint: rd.fingerprint
      };
    });
  }

  /*
   * Legacy lookup function (used everywhere in node.js)
   */

  legacy(hostname, options, callback) {
    let hints = 0;
    let family = -1;
    let all = false;
    let verbatim = false;

    if (hostname && typeof hostname !== 'string') {
      throw makeTypeError('ERR_INVALID_ARG_TYPE', 'hostname');
    } else if (typeof options === 'function') {
      callback = options;
      family = 0;
    } else if (typeof callback !== 'function') {
      throw makeTypeError('ERR_INVALID_CALLBACK', 'callback');
    } else if (options !== null && typeof options === 'object') {
      hints = options.hints >>> 0;
      family = options.family >>> 0;
      all = options.all === true;
      verbatim = options.verbatim === true;

      if (hints !== 0 &&
          hints !== this.ADDRCONFIG &&
          hints !== this.V4MAPPED &&
          hints !== (this.ADDRCONFIG | this.V4MAPPED)) {
        throw makeTypeError('ERR_INVALID_OPT_VALUE', 'hints');
      }
    } else {
      family = options >>> 0;
    }

    if (family !== 0 && family !== 4 && family !== 6)
      throw makeTypeError('ERR_INVALID_OPT_VALUE', 'family');

    const opt = {
      hints,
      family,
      all,
      verbatim
    };

    if (!hostname && hostname != null)
      hostname = null;

    this.lookup(hostname, opt).then((result) => {
      if (!all) {
        const {address, family} = result;
        process.nextTick(() => callback(null, address, family));
      } else {
        process.nextTick(() => callback(null, result));
      }
    }).catch((err) => {
      process.nextTick(() => callback(err));
    });
  }

  static make(create, options) {
    const keys = Object.getOwnPropertyNames(this.prototype);
    const api = new this(create, options);

    for (const key of keys) {
      const func = api[key];

      if (typeof func !== 'function')
        continue;

      if (key.length === 0)
        continue;

      if (key === 'constructor')
        continue;

      if (key[0] === '_')
        continue;

      api[key] = func.bind(api);
    }

    return api;
  }
}

/*
 * Helpers
 */

function makeError(name, syscall, code) {
  const err = new Error(`${syscall} ${code} ${name}`);
  err.errno = code;
  err.code = code;
  err.syscall = syscall;
  err.hostname = name;
  return err;
}

function makeQueryError(name, type, code) {
  const syscall = `query${constants.typeToString(type)}`;
  return makeError(name, syscall, code);
}

function makeGAIError(name, code) {
  return makeError(name, 'getaddrinfo', code);
}

function makeGNIError(name, code) {
  return makeError(name, 'getnameinfo', code);
}

function makeTypeError(code, arg) {
  const err = new TypeError(`Invalid argument: "${arg}".`);
  err.code = code;
  err.name = `TypeError [${code}]`;
  return err;
}

/*
 * Expose
 */

module.exports = API;
