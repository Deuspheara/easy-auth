'use strict';
const assert = require('node:assert/strict');
const {spawn} = require('node:child_process');
const readline = require('node:readline');
const path = require('node:path');
const root = path.resolve(__dirname, '../../..');

async function withFixture(action) {
  assert.equal(['darwin', 'linux'].includes(process.platform), true);
  const child = spawn(path.join(root, 'target/debug/examples/passkey-recovery-browser'), [], {
    cwd: root, env: process.env, detached: true, stdio: ['pipe', 'pipe', 'pipe']
  });
  let readyResolve, readyReject, removed = false, diagnostic = false, database;
  const ready = new Promise((resolve, reject) => { readyResolve = resolve; readyReject = reject; });
  const lines = readline.createInterface({input: child.stdout});
  lines.on('line', line => {
    try {
      const item = JSON.parse(line);
      if (item.origin) readyResolve(item.origin);
      if (item.fixture_database_removed === true) removed = true;
      if (item.database) database = item.database;
    } catch { readyReject(new Error('fixture output shape')); }
  });
  child.stderr.on('data', () => { diagnostic = true; });
  child.on('error', () => readyReject(new Error('fixture startup')));
  const exited = new Promise(resolve => child.on('close', code => {
    readyReject(new Error('fixture stopped'));
    resolve(code);
  }));
  let failure, result, exit;
  try {
    const origin = await Promise.race([ready, new Promise((_, reject) => {
      const timer = setTimeout(() => reject(new Error('fixture readiness')), 30000); timer.unref();
    })]);
    const url = new URL(origin);
    assert.equal(url.protocol, 'http:');
    assert.equal(url.hostname, 'localhost');
    assert.equal(url.username + url.password + url.search + url.hash, '');
    result = await action(origin);
  } catch (error) { failure = error; }
  finally {
    child.stdin.end();
    if (child.exitCode === null) child.kill('SIGINT');
    exit = await Promise.race([exited, new Promise(resolve => {
      const timer = setTimeout(() => resolve('timeout'), 10000); timer.unref();
    })]);
    if (exit === 'timeout') {
      try { process.kill(-child.pid, 'SIGKILL'); } catch { /* owned group already stopped */ }
      child.stdout.destroy(); child.stderr.destroy();
    }
    lines.close();
  }
  const cleanup = exit === 0 && removed && !diagnostic;
  if (failure) { failure.cleanupVerified = cleanup; throw failure; }
  assert.equal(cleanup, true, 'normal owned fixture cleanup and no native diagnostics');
  return {result, database, fixture_database_removed: removed};
}
module.exports = {withFixture};
