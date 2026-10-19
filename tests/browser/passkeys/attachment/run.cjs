'use strict';
const assert = require('node:assert/strict');
const {spawn, execFileSync} = require('node:child_process');
const crypto = require('node:crypto');
const fs = require('node:fs');
const path = require('node:path');
const readline = require('node:readline');
const {chromium} = require('playwright');
const {mailbox} = require('./mail.cjs');
const {runCases} = require('./cases.cjs');
const {runRecoveryCases} = require('./recovery.cjs');
const root = path.resolve(__dirname, '../../../..');

async function main() {
  assert.equal(['darwin', 'linux'].includes(process.platform), true, 'owned process-group fixture requires Unix');
  const mail = mailbox(process.env.EASY_AUTH_MAILPIT_URL || 'http://127.0.0.1:8025', crypto.randomUUID());
  const binary = process.env.EASY_AUTH_SMTP_TEST_BINARY || path.join(root, 'target/debug/examples/passkey-smtp-browser');
  // Own a new process group so timeout escalation cannot leave the nested SMTP
  // server running or signal unrelated processes. No shell or inherited group.
  const child = spawn(binary, [], {cwd: root, env: process.env, detached: true,
    stdio: ['ignore', 'pipe', 'pipe']});
  let readyResolve, readyReject, removed = false, database, diagnostic = false;
  const ready = new Promise((resolve, reject) => { readyResolve = resolve; readyReject = reject; });
  const lines = readline.createInterface({input: child.stdout});
  lines.on('line', line => {
    try {
      const value = JSON.parse(line);
      if (value.origin) readyResolve(value.origin);
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
    results = await runCases(browser, origin, mail);
    results.push(...await runRecoveryCases(browser, origin, mail));
  } catch (error) { failure = error; }
  finally {
    if (browser) await browser.close();
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
  for (const field of ['users', 'strong_verified_users', 'credentials', 'signup_audits', 'attachment_audits']) {
    assert.equal(database[field], 4, field);
  }
  assert.equal(database.authentication_audits, 8);
  assert.equal(database.management_renames, 2);
  assert.equal(database.management_removals, 2);
  assert.equal(database.management_notices_pending, 0);
  assert.equal(database.unproven_remaining_keys, 0);
  for (const field of ['weak_sessions', 'invalid_attachment_provenance', 'attachment_pending', 'signup_pending']) {
    assert.equal(database[field], 0, field);
  }
  assert.equal(database.recovery_configured, 4);
  assert.equal(database.recovery_codes, 2);
  assert.equal(database.recovery_setups_pending, 0);
  assert.equal(database.recovery_notices_pending, 0);
  assert.equal(database.invalid_recovery_provenance, 0);
  assert.equal(cleanup.messages_removed, 11, 'seven prior management/contact messages plus two new contacts and two recovery configuration notices');
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
    fixture: 'owned disposable PostgreSQL; real configured_auth SMTP adapter; loopback Mailpit; original native resident signup; no seeded session or key metadata mutation',
    cases: results, database, fixture_database_removed: removed, ...cleanup};
  if (process.env.EASY_AUTH_TEST_REPORT) fs.writeFileSync(process.env.EASY_AUTH_TEST_REPORT, JSON.stringify(report, null, 2) + '\n');
  console.log(JSON.stringify({passed: results.length, chromium: version, database,
    fixture_database_removed: removed, ...cleanup}));
}
main().catch(error => {
  // Never echo assertion values, message bodies, proof URLs, cookies or child output.
  console.error('SMTP browser suite failed:', error.caseName || 'startup/cleanup', error.stageName || 'case', error.name);
  process.exitCode = 1;
});
