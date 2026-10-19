'use strict';
const assert = require('node:assert/strict');
const {spawn, execFileSync} = require('node:child_process');
const crypto = require('node:crypto');
const fs = require('node:fs');
const path = require('node:path');
const readline = require('node:readline');
const {chromium} = require('playwright');
const {mailbox} = require('../attachment/mail.cjs');
const {runPages} = require('./cases.cjs');
const {manualBootstrap} = require('./manual.cjs');
const {sameDeviceRecovery} = require('./same-device.cjs');
const root = path.resolve(__dirname, '../../../..');

async function main() {
  assert.equal(['darwin', 'linux'].includes(process.platform), true, 'owned process-group fixture requires Unix');
  const mail = mailbox(process.env.EASY_AUTH_MAILPIT_URL || 'http://127.0.0.1:8025', crypto.randomUUID());
  const binary = process.env.EASY_AUTH_RECOVERY_TEST_BINARY || path.join(root, 'target/debug/examples/passkey-recovery-browser');
  // Own a new process group so timeout escalation cannot leave the nested SMTP
  // server running or signal unrelated processes. No shell or inherited group.
  const child = spawn(binary, [], {cwd: root, env: process.env, detached: true,
    stdio: ['pipe', 'pipe', 'pipe']});
  let readyResolve, readyReject, removed = false, database, diagnostic = false;
  let controlResolve, controlKey;
  async function control(command, key) {
    controlKey = key;
    return new Promise((resolve, reject) => {
      const timer = setTimeout(() => reject(new Error('owned fixture control timeout')), 5000);
      controlResolve = value => {clearTimeout(timer);resolve(value);};
      child.stdin.write(command + '\n');
    });
  }
  async function prepareClock(owner) {
    const deadline = Date.now() + 5000;
    do {
      if (await control('mature-owned-claim ' + owner, 'recovery_clock_prepared')) return;
      await new Promise(resolve => setTimeout(resolve, 100));
    } while (Date.now() < deadline);
    throw new Error('actual notification receipt required before clock fixture');
  }
  const ready = new Promise((resolve, reject) => { readyResolve = resolve; readyReject = reject; });
  const lines = readline.createInterface({input: child.stdout});
  lines.on('line', line => {
    try {
      const value = JSON.parse(line);
      if (value.origin) readyResolve(value.origin);
      if (typeof value[controlKey] === "boolean") controlResolve?.(value[controlKey]);
      if (value.database) database = value.database;
      if (value.fixture_database_removed === true) removed = true;
    } catch { readyReject(new Error('unexpected fixture output')); }
  });
  child.stderr.on('data', () => { diagnostic = true; });
  child.on('error', readyReject);
  const exited = new Promise(resolve => child.on('close', code => {
    readyReject(new Error('fixture stopped before readiness'));
    resolve(code);
  }));
  let browser, results, version, mailpitVersion, failure, cleanup;
  try {
    const origin = await Promise.race([ready, new Promise((_, reject) => {
      const timer = setTimeout(() => reject(new Error('fixture readiness timeout')), 30000); timer.unref();
    })]);
    assert.equal(new URL(origin).hostname, 'localhost');
    mailpitVersion = await mail.version();
    browser = await chromium.launch({headless: true});
    version = browser.version();
    results = await runPages(browser, origin, mail, prepareClock);
    results.push(await manualBootstrap(browser, origin));
    results.push(await sameDeviceRecovery(browser, origin, prepareClock));
    const deadline = Date.now() + 5000;
    while (!await control('observe-owned-notices', 'recovery_notices_drained')) {
      assert.equal(Date.now() < deadline, true, 'actual worker acknowledgements must drain owned queue');
      await new Promise(resolve => setTimeout(resolve, 100));
    }
  } catch (error) { failure = error; }
  finally {
    if (browser) await browser.close();
    child.stdin.end();
    if (child.exitCode === null) child.kill('SIGINT');
    const stopped = await Promise.race([exited, new Promise(resolve => {
      const timer = setTimeout(() => resolve('timeout'), 10000); timer.unref();
    })]);
    if (stopped === 'timeout') {
      try { process.kill(-child.pid, 'SIGKILL'); } catch { /* group may already have exited */ }
      child.stdout.destroy();
      child.stderr.destroy();
      failure ||= new Error('fixture cleanup unverified');
    } else if (stopped !== 0 || !removed) failure ||= new Error('fixture cleanup failed');
    lines.close();
    try { cleanup = await mail.cleanup(); } catch { failure ||= new Error('owned mail cleanup failed'); }
  }
  if (failure) {
    console.log(JSON.stringify({fixture_database_removed: removed, ...cleanup}));
    throw failure;
  }
  assert.equal(diagnostic, false, 'no unexpected fixture diagnostics');
  for (const field of ['users', 'credentials', 'signup_audits', 'recovery_codes']) assert.equal(database[field], 9, field);
  assert.equal(database.recovery_started, 8);
  for (const field of ['strong_verified_users','attachment_audits','recovery_cancelled']) assert.equal(database[field], 3, field);
  assert.equal(database.recovery_completed, 5);
  assert.equal(database.recovery_configured, 14);
  assert.equal(database.recovery_codes_unused, 6);
  for (const field of ['recovery_candidates','recovery_registrations_pending','recovery_assertions_pending','recovery_pending','recovery_notices_pending_all','invalid_completion_provenance','weak_sessions','invalid_recovery_provenance','recovery_setups_pending','unproven_remaining_keys','signup_pending','attachment_pending']) assert.equal(database[field], 0, field);
  assert.equal(database.recovery_source_attempts <= 40, true, 'original source admission remains intact');
  assert.equal(cleanup.messages_removed, 14, 'only exact owned contact/configuration/start/completion/cancellation notices');
  const sources = execFileSync('git', ['ls-files', '--cached', '--others', '--exclude-standard', '-z'], {cwd: root})
    .toString().split('\0').filter(name => name && !name.includes('/results/') &&
      (/\.(rs|sql|toml|cjs|js|html|json|yml|yaml)$/.test(name) || name === 'Cargo.lock'));
  const report = {recorded_at: new Date().toISOString(), node: process.version,
    playwright: require('playwright/package.json').version, chromium: version, mailpit: mailpitVersion,
    platform: process.platform, arch: process.arch,
    source_base_revision: execFileSync('git', ['rev-parse', 'HEAD'], {cwd: root}).toString().trim(),
    fixture_binary_sha256: crypto.createHash('sha256').update(fs.readFileSync(binary)).digest('hex'),
    source_sha256: sources.map(name => ({path: name, sha256: crypto.createHash('sha256')
      .update(fs.readFileSync(path.join(root, name))).digest('hex')})),
    fixture: 'owned disposable PostgreSQL; real configured_auth SMTP; original native resident signup/replacement; trusted elapsed-claim timestamps only after actual required receipt; original expiry unchanged; no seeded session/key/receipt or production clock override',
    cases: results, database, fixture_database_removed: removed, ...cleanup};
  if (process.env.EASY_AUTH_TEST_REPORT) fs.writeFileSync(process.env.EASY_AUTH_TEST_REPORT, JSON.stringify(report, null, 2) + '\n');
  console.log(JSON.stringify({passed: results.length, chromium: version, database,
    fixture_database_removed: removed, ...cleanup}));
}
main().catch(error => {
  // Never echo assertion values, message bodies, proof URLs, cookies or child output.
  const frame = error.stack?.match(/recovery\/(cases|setup|cancellation|manual|same-device|prompt-errors)\.cjs:(\d+)/);
  console.error('Recovery pages suite failed:', error.caseName || 'startup/cleanup', error.stageName || 'case', error.name, frame ? frame[1] + ':' + frame[2] : 'fixture');
  process.exitCode = 1;
});
