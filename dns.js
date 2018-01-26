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
  Question,
  Record,
  ARecord,
  AAAARecord,
  types,
  classes,
  codes,
  opcodes
} = wire;

const server = dgram.createSocket('udp4');

function dir(obj) {
  console.dir(obj, { depth: 20, customInspect: true, colors: true });
}

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
  res.code = codes.NOERROR;
  res.question = msg.question;

  for (const q of msg.question) {
    if (q.class !== classes.INET
        && q.class !== classes.ANY) {
      continue;
    }

    const answer = new Record();
    answer.name = q.name;
    answer.class = classes.INET;

    if (q.type === types.A || q.type === types.ANY) {
      answer.type = types.A;
      answer.data = new ARecord();
    } else if (q.type === types.AAAA) {
      answer.type = types.AAAA;
      answer.data = new AAAARecord();
    } else {
      continue;
    }

    res.answer.push(answer);
  }

  server.send(res.toRaw(), port, address);

  dir(msg);
  dir(res);
  dir(Message.fromRaw(res.toRaw()));
});

server.on('listening', () => {
  const address = server.address();
  console.log(`server listening ${address.address}:${address.port}`);
});

// $ dig @127.0.0.1 google.com -p 41234
//server.bind(41234);

const socket = dgram.createSocket('udp4');

socket.on('error', (err) => {
  console.log(`server error:\n${err.stack}`);
  socket.close();
});

socket.on('message', (data, {port, address}) => {
  const msg = Message.fromRaw(data);
  dir(msg);
});

function resolve() {
  const req = new Message();
  req.id = 101;
  req.opcode = opcodes.QUERY;

  const q = new Question();
  q.name = 'com.';
  q.type = types.ANY;
  q.class = classes.INET;

  req.question.push(q);

  const msg = req.toRaw();
  socket.send(msg, 0, msg.length, 53, '208.67.222.222');
}

socket.bind(() => {
  // socket.setBroadcast(true);
  // socket.setMulticastTTL(128);
  // socket.addMembership('8.8.8.8');
  resolve();
});
