'use strict';

const fs = require('fs');

const {
  argv,
  exit,
  stdin,
  stderr
} = process;

async function readInput(arg) {
  return new Promise((resolve, reject) => {
    if (argv.length > 2) {
      if (arg) {
        resolve(['/dev/stdin', ...argv.slice(2)]);
        return;
      }

      if (argv[2] !== '-') {
        fs.readFile(argv[2], 'utf8', (err, text) => {
          if (err) {
            reject(err);
            return;
          }
          resolve([argv[2], text, ...argv.slice(3)]);
        });
        return;
      }
    }

    let input = '';

    stdin.setEncoding('utf8');
    stdin.resume();

    stdin.on('error', reject);

    stdin.on('data', (str) => {
      input += str;
    });

    stdin.on('end', () => {
      resolve(['/dev/stdin', input, ...argv.slice(2)]);
    });
  });
}

async function _read(callback, arg) {
  try {
    const args = await readInput(arg);
    await callback(...args);
  } catch (e) {
    stderr.write(e.stack + '\n');
    exit(1);
  }
}

function read(callback) {
  _read(callback, false);
}

function readArg(callback) {
  _read(callback, true);
}

exports.read = read;
exports.readArg = readArg;
