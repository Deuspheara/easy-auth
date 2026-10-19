'use strict';
const assert = require('node:assert/strict');
const {spawn, execFileSync} = require('node:child_process');
const crypto = require('node:crypto');
const fs = require('node:fs');
const path = require('node:path');
const readline = require('node:readline');
const {chromium} = require('playwright');
const {runCases} = require('./cases.cjs');
const {runAuthenticationCases} = require('./authentication.cjs');

const root = path.resolve(__dirname, '../../..');

function fingerprints() {
  const files = execFileSync('git', ['ls-files', '--cached', '--others', '--exclude-standard', '-z'], {cwd: root})
    .toString().split('\0').filter(name => name && (
      name.endsWith('.rs') || name.endsWith('.sql') || name.endsWith('Cargo.toml') || name === 'Cargo.lock' ||
      name.startsWith('tests/browser/passkeys/') && /\.(cjs|json)$/.test(name) && !name.includes('/results/')
    ));
  return files.map(name => ({path: name, sha256: crypto.createHash('sha256')
    .update(fs.readFileSync(path.join(root, name))).digest('hex')}));
}

async function main() {
  const sessions = Array.from({length: 20}, () => crypto.randomBytes(32).toString('base64url'));
  const binary = process.env.EASY_AUTH_PASSKEY_TEST_BINARY || path.join(root, 'target/debug/examples/passkey-browser');
  // Generated test credentials go only through the child environment and loopback
  // fixture cookies. Never log them or persist browser traces/storage state.
  const child = spawn(binary, [], {cwd: root, env: {...process.env,
    EASY_AUTH_TEST_SESSIONS: JSON.stringify(sessions)}, stdio: ['pipe', 'pipe', 'pipe']});
  let counterlessResolve;
  async function prepareCounterless() {
    await new Promise((resolve, reject) => {
      const timer = setTimeout(() => reject(new Error('counterless fixture setup timeout')), 5000);
      counterlessResolve = prepared => {
        clearTimeout(timer);
        if (prepared) resolve(); else reject(new Error('counterless fixture setup failed'));
      };
      child.stdin.end('prepare-counterless-fixture\n');
    });
  }
  let summary, removed = false, stderr = '';
  let readyResolve, readyReject;
  const ready = new Promise((resolve, reject) => { readyResolve = resolve; readyReject = reject; });
  const lines = readline.createInterface({input: child.stdout});
  lines.on('line', line => {
    try {
      const value = JSON.parse(line);
      if (value.origin) readyResolve(value.origin);
      if (Number.isInteger(value.credentials)) summary = value;
      if (value.fixture_database_removed === true) removed = true;
      if (typeof value.counterless_fixture_prepared === 'boolean') counterlessResolve?.(value.counterless_fixture_prepared);
    } catch { readyReject(new Error('unexpected fixture output')); }
  });
  child.stderr.on('data', data => { stderr += data.toString(); });
  child.on('error', readyReject);
  const exited = new Promise(resolve => child.on('close', (code, signal) => {
    readyReject(new Error('fixture stopped before readiness'));
    resolve({code, signal});
  }));
  let browser, results, origin, version, failure;
  try {
    origin = await Promise.race([ready, new Promise((_, reject) => {
      const timer = setTimeout(() => reject(new Error('fixture startup timeout')), 30000); timer.unref();
    })]);
    const url = new URL(origin);
    assert.equal(url.hostname, 'localhost');
    assert.equal(url.protocol, 'http:');
    browser = await chromium.launch({headless: true});
    version = browser.version();
    results = await runCases(browser, origin, sessions);
    results.push(...await runAuthenticationCases(browser, origin, sessions.slice(results.length), prepareCounterless));
  } catch (error) { failure = error; }
  finally {
    if (browser) await browser.close();
    if (!child.stdin.writableEnded) child.stdin.end();
    if (child.exitCode === null) child.kill('SIGINT');
    const stopped = await Promise.race([exited, new Promise(resolve => {
      const timer = setTimeout(() => resolve({timeout: true}), 10000); timer.unref();
    })]);
    if (stopped.timeout) {
      child.kill('SIGKILL');
      failure ||= new Error('fixture did not cleanly stop; disposable database cleanup unverified');
    } else if (stopped.code !== 0 || !removed) {
      failure ||= new Error('fixture cleanup failed');
    }
    lines.close();
  }
  if (failure) {
    console.log(JSON.stringify({fixture_database_removed: removed, database: summary || null}));
    throw failure;
  }
  assert.equal(stderr, '', 'fixture must not emit unexpected diagnostic output');
  assert.equal(summary.credentials, results.length, 'each case commits one genuine registration');
  assert.equal(summary.audits, results.length, 'audit count matches committed credentials');
  assert.equal(summary.pending, 0, 'all cases finish or consume their original ceremony');
  const authentications = results.reduce((total, result) => total + (result.authentications || 0), 0);
  assert.equal(summary.authentication_audits, authentications, 'each verified sign-in commits one audit');
  assert.equal(summary.passkey_sessions, authentications, 'each verified sign-in commits one session');
  assert.equal(summary.authentication_pending, 0, 'valid completions and explicit counterless fixture reset leave no pending state');
  assert.equal(summary.authentication_finish_attempts, 23, 'all signed negatives reached admitted core verification');
  assert.equal(summary.backed_up_credentials, 1, 'eligible backup-state change persisted');
  assert.equal(summary.zero_counter_credentials, 1, 'counterless credential state persisted');
  const report = {recorded_at: new Date().toISOString(), node: process.version, playwright: require('playwright/package.json').version,
    chromium: version, platform: process.platform, arch: process.arch,
    rustc: execFileSync('rustc', ['--version']).toString().trim(),
    fixture_binary_sha256: crypto.createHash('sha256').update(fs.readFileSync(binary)).digest('hex'),
    source_base_revision: execFileSync('git', ['rev-parse', 'HEAD'], {cwd: root}).toString().trim(),
    source_sha256: fingerprints(), fixture: 'loopback; disposable PostgreSQL; seeded verified sessions; one trusted counterless storage fixture',
    cases: results, database: summary, fixture_database_removed: removed};
  if (process.env.EASY_AUTH_TEST_REPORT) {
    const destination = path.resolve(process.env.EASY_AUTH_TEST_REPORT);
    fs.mkdirSync(path.dirname(destination), {recursive: true});
    fs.writeFileSync(destination, JSON.stringify(report, null, 2) + '\n');
  }
  console.log(JSON.stringify({passed: results.length, chromium: version, database: summary,
    fixture_database_removed: removed}));
}

main().catch(error => {
  // Assertions contain controlled labels/status codes, never protocol payloads.
  console.error('passkey browser suite failed:', error.name,
    error.caseName || 'startup/cleanup',
    error.code === 'ERR_ASSERTION' ? error.message : 'browser/fixture execution error');
  process.exitCode = 1;
});
