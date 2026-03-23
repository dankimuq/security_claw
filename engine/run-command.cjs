#!/usr/bin/env node
const { spawnSync } = require('child_process');

if (process.argv.length < 4) {
  console.error('Usage: node engine/run-command.cjs <command-json> <cwd>');
  process.exit(2);
}

const commandSpec = JSON.parse(process.argv[2]);
const cwd = process.argv[3];

if (!commandSpec || typeof commandSpec.command !== 'string' || !Array.isArray(commandSpec.args)) {
  console.error('Invalid command specification. Expected { command, args }.');
  process.exit(2);
}

const result = spawnSync(commandSpec.command, commandSpec.args, {
  cwd,
  stdio: 'inherit',
  shell: false,
  env: process.env,
});

if (typeof result.status === 'number') {
  process.exit(result.status);
}

process.exit(1);