'use strict';

// https://github.com/miekg/dns/blob/master/msg.go
// https://github.com/miekg/dns/blob/master/msg_helpers.go
// https://github.com/miekg/dns/blob/master/types.go
// https://github.com/tigeli/bind-utils/blob/1acae3ea5e3048ebd121d4837ef989b57a05e54c/lib/dns/name.c

const assert = require('assert');
const dgram = require('dgram');
const bio = require('bufio');
const wire = require('./wire');

const {
  Message,
  Record,
  types,
  classes,
  codes,
  opcodes
} = wire;

const server = dgram.createSocket('udp4');

server.on('error', (err) => {
  console.log(`server error:\n${err.stack}`);
  server.close();
});

server.on('message', (data, {port, address}) => {
  const msg = Message.fromRaw(data);

  if (msg.opcode !== opcodes.QUERY)
    return;

  if (msg.question.length === 0)
    return;

  const res = new Message();
  res.id = msg.id;
  res.opcode = msg.opcode;
  res.response = true;

  for (const q of msg.question) {
    if (q.class !== classes.INET
        && q.class !== classes.ANY) {
      continue;
    }

    const answer = new Record();
    answer.code = codes.SUCCESS;
    answer.name = q.name;
    answer.class = classes.INET;

    if (q.type === types.A || q.type === types.ANY) {
      answer.type = types.A;
      answer.data = Buffer.from([1,2,3,4]);
    } else if (q.type === types.AAAA) {
      answer.type = types.AAAA;
      answer.data = Buffer.alloc(16, 0xff);
    } else {
      continue;
    }

    res.answer.push(answer);
  }

  server.send(res.toRaw(), port, address);

  console.log(msg);
  console.log(res);
  console.log(Message.fromRaw(res.toRaw()));
});

server.on('listening', () => {
  const address = server.address();
  console.log(`server listening ${address.address}:${address.port}`);
});

// $ dig @127.0.0.1 google.com -p 41234

server.bind(41234);
