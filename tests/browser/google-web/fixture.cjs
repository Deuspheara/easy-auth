'use strict';
const assert = require('node:assert/strict');
const {spawn, execFileSync} = require('node:child_process');
const readline = require('node:readline');

function start(binary, root, origin) {
  const child = spawn(binary, [origin], {cwd: root, env: process.env, stdio: ['ignore', 'pipe', 'pipe']});
  let resolveReady, rejectReady, removed = false, database, facts, diagnostic = false;
  const ready = new Promise((resolve, reject) => {resolveReady = resolve; rejectReady = reject;});
  const lines = readline.createInterface({input: child.stdout});
  lines.on('line', line => {
    try {
      const value = JSON.parse(line);
      if (value.database) database = value.database;
      if (value.address) resolveReady(value.address);
      if (value.facts) facts = value.facts;
      if (value.fixture_database_removed === true) removed = true;
    } catch {rejectReady(new Error('invalid owned fixture IPC'));}
  });
  child.stderr.on('data', () => {diagnostic = true;});
  child.on('error', () => rejectReady(new Error('owned fixture could not start')));
  const exited = new Promise(resolve => child.on('close', code => {rejectReady(new Error('owned fixture exited')); resolve(code);}));
  return {ready,
    async close() {
      if (child.exitCode === null && child.signalCode === null) child.kill('SIGINT');
      let timer;
      const code = await Promise.race([exited, new Promise(resolve => {timer = setTimeout(() => resolve('timeout'), 10000);})]);
      clearTimeout(timer);
      if (code === 'timeout') {child.kill('SIGKILL'); await exited;}
      lines.close();
      let emergency = false;
      if (!removed && database) {
        assert.match(database, /^easy_auth_oidc_[0-9a-f]{32}$/);
        execFileSync(binary, ['--remove-owned-database', database], {cwd: root, env: process.env, stdio: 'ignore', timeout: 10000});
        emergency = true;
      }
      return {stopped: code === 0, database_removed: removed, emergency_cleanup: emergency, diagnostic, facts};
    }
  };
}
module.exports = {start};
