'use strict';

const fs = require('fs');

const {
  argv,
  exit,
  stdin,
  stderr
} = process;

async function readInput() {
  return new Promise((resolve, reject) => {
    if (argv.length > 2 && argv[2] !== '-') {
      fs.readFile(argv[2], 'utf8', (err, text) => {
        if (err) {
          reject(err);
          return;
        }
        resolve(text);
      });
      return;
    }

    let input = '';

    stdin.setEncoding('utf8');
    stdin.resume();

    stdin.on('error', reject);

    stdin.on('data', (str) => {
      input += str;
    });

    stdin.on('end', () => resolve(input));
  });
}

async function _read(callback) {
  try {
    await callback(await readInput());
  } catch (e) {
    stderr.write(e.message + '\n');
    exit(1);
  }
}

function read(callback) {
  _read(callback);
}

module.exports = read;
