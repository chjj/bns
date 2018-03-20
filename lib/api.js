/*!
 * api.js - node.js api for bns
 * Copyright (c) 2018, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bns
 */

'use strict';

const assert = require('assert');
const IP = require('binet');
const constants = require('./constants');
const encoding = require('./encoding');
const ResolvConf = require('./resolvconf');
const {StubResolver, OSResolver} = require('./resolver');
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
const conf = ResolvConf.fromSystem();

/**
 * API
 */

class API {
  constructor() {
    this.Resolver = this.constructor;

    this.ADDRCONFIG = 32;
    this.V4MAPPED = 8;

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
    this.INSECURE = 'EINSECURE'; // custom

    this._servers = conf.getServers();
  }

  async _stub() {
    const resolver = new StubResolver();
    resolver.setServers(this._servers);
    return resolver.open();
  }

  async _os() {
    const resolver = new OSResolver();
    return resolver.open();
  }

  async _query(resolver, name, type) {
    assert(resolver);
    assert(typeof name === 'string');
    assert((type & 0xffff) === type);

    let res;
    try {
      res = await resolver.lookup(name, type);
    } catch (e) {
      if (e.message === 'Request timed out.')
        throw makeQueryError(name, type, this.TIMEOUT);
      throw makeQueryError(name, type, this.BADRESP);
    } finally {
      await resolver.close();
    }

    return res;
  }

  async _execute(resolver, name, type, secure, map) {
    assert(resolver);
    assert(typeof map === 'function');

    const res = await this._query(resolver, name, type);

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

    const rrs = res.collect(name, type);
    const result = [];

    for (const rr of rrs) {
      const obj = map(rr);
      if (obj)
        result.push(obj);
    }

    if (result.length === 0)
      throw makeQueryError(name, type, this.NODATA);

    return result;
  }

  async _resolve(name, type, map) {
    return this._execute(await this._stub(), name, type, false, map);
  }

  async _lookup(name, type, map) {
    return this._execute(await this._os(), name, type, false, map);
  }

  async _resolveSecure(name, type, map) {
    return this._execute(await this._stub(), name, type, true, map);
  }

  async _lookupSecure(name, type, map) {
    return this._execute(await this._os(), name, type, true, map);
  }

  getServers() {
    return this._servers.slice();
  }

  setServers(servers) {
    assert(Array.isArray(servers));

    this._servers = [];

    for (const server of servers) {
      const addr = IP.fromHost(server, 53);
      assert(addr.type === 4 || addr.type === 6);
      this._servers.push(addr.hostname);
    }

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

  async reverse(ip) {
    const name = encoding.reverse(ip);
    return this._resolve(name, types.PTR, (rr) => {
      return util.trimFQDN(rr.data.ptr);
    });
  }

  async _lookup4(name, addrs, map) {
    try {
      await this._lookup(name, types.A, (rr) => {
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
      await this._lookup(name, types.AAAA, (rr) => {
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

    assert(typeof name === 'string');
    assert(options && typeof options === 'object');

    const family = options.family >>> 0;
    const hints = options.hints >>> 0;
    const all = Boolean(options.all);

    assert(family === 0 || family === 4 || family === 6);

    assert(hints === 0
      || hints === this.ADDRCONFIG
      || hints === this.V4MAPPED
      || hints === (this.ADDRCONFIG | this.V4MAPPED));

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

  async lookupService(ip, port) {
    port = port >>> 0;

    assert(typeof ip === 'string');
    assert((port & 0xffff) === port);

    const name = encoding.reverse(ip);

    const ptrs = await this._lookup(name, types.PTR, (rr) => {
      return util.trimFQDN(rr.data.ptr);
    });

    if (ptrs.length === 0)
      throw makeGNIError(name, this.NOTFOUND);

    return { hostname: ptrs[0], service: null };
  }

  /*
   * Non-standard node.js API
   */

  async resolveRaw(name, type) {
    return this._query(await this._stub(), name, type);
  }

  async lookupRaw(name, type) {
    return this._query(await this._os(), name, type);
  }

  async lookupTLSA(name, cert, protocol, port) {
    assert(Buffer.isBuffer(cert));
    assert(protocol == null || typeof protocol === 'string');
    assert(port == null || (port & 0xffff) === port);

    return this._lookupSecure(name, types.TLSA, (rr) => {
      const rd = rr.data;

      if (!tlsa.verify(rr, cert, name, protocol, port))
        return null;

      let decoded;
      try {
        decoded = tlsa.decodeName(rr.name);
      } catch (e) {
        return null;
      }

      return {
        protocol: decoded.protocol,
        port: decoded.port,
        usage: rd.usage
      };
    });
  }

  async lookupSMIMEA(name, cert, email) {
    assert(Buffer.isBuffer(cert));
    assert(email == null || typeof email === 'string');

    return this._lookupSecure(name, types.SMIMEA, (rr) => {
      const rd = rr.data;

      if (!smimea.verify(rr, cert, name, email))
        return null;

      let decoded;
      try {
        decoded = smimea.decodeName(rr.name);
      } catch (e) {
        return null;
      }

      return {
        hash: decoded.hash,
        usage: rd.usage
      };
    });
  }

  async lookupSSHFP(name, key) {
    assert(Buffer.isBuffer(key));

    return this._lookupSecure(name, types.SSHFP, (rr) => {
      const rd = rr.data;

      if (!sshfp.verify(rr, key))
        return null;

      return {
        algorithm: rd.algorithm,
        digestType: rd.digestType,
        fingerprint: rd.fingerprint
      };
    });
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

/*
 * Expose
 */

module.exports = API;
