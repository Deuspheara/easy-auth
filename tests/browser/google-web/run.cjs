'use strict';
const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const {execFileSync} = require('node:child_process');
const {chromium} = require('../passkeys/node_modules/playwright');
const tlsProxy = require('../oidc/proxy.cjs');
const fixture = require('./fixture.cjs');
const cases = require('./cases.cjs');
const root = path.resolve(__dirname, '../../..');

async function main() {
  const binary = process.env.EASY_AUTH_GOOGLE_WEB_TEST_BINARY || path.join(root, 'target/debug/examples/google-web-browser');
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'easy-auth-google-web-'));
  let proxy, owned, browser, cleanup, results, version, failure, timer;
  try {
    proxy = await tlsProxy.start(directory);
    const origin = 'https://app.example:' + new URL(proxy.origin).port;
    owned = fixture.start(binary, root, origin);
    const address = await Promise.race([owned.ready, new Promise((_, reject) => {timer = setTimeout(() => reject(new Error('owned readiness timeout')), 30000);})]);
    clearTimeout(timer);
    proxy.connectApplication('http://' + address, origin);
    browser = await chromium.launch({headless: true, args: ['--host-resolver-rules=MAP app.example 127.0.0.1']});
    version = browser.version();
    results = await Promise.race([cases.run(browser, origin), new Promise((_, reject) => {timer = setTimeout(() => reject(new Error('owned browser deadline')), 60000);})]);
  } catch (error) {failure = error;}
  finally {
    clearTimeout(timer);
    for (const action of [async () => {if (browser) await browser.close();}, async () => {if (owned) cleanup = await owned.close();}, async () => {if (proxy) await proxy.close();}]) {
      try {await action();} catch (error) {failure ||= error;}
    }
    fs.rmSync(directory, {recursive: true, force: true});
  }
  if (failure) {console.log(JSON.stringify({cleanup})); throw failure;}
  assert.deepEqual(cleanup, {stopped: true, database_removed: true, emergency_cleanup: false, diagnostic: false,
    facts: {users: 0, identities: 0, sessions: 0, audit: 2, pending: 0, posts: 5, signed: 5}});
  assert.equal(results.length, 13);
  const sources = execFileSync('git', ['ls-files', '--cached', '--others', '--exclude-standard', '-z'], {cwd: root}).toString().split('\0')
    .filter(name => name && !name.includes('/results/') && (/\.(rs|sql|toml|cjs|js|html|json|yml|yaml|py)$/.test(name) || name === 'Cargo.lock'));
  const report = {recorded_at: new Date().toISOString(), node: process.version, chromium: version,
    playwright: require('../passkeys/node_modules/playwright/package.json').version, platform: process.platform, arch: process.arch,
    source_base_revision: execFileSync('git', ['rev-parse', 'HEAD'], {cwd: root}).toString().trim(),
    fixture_binary_sha256: crypto.createHash('sha256').update(fs.readFileSync(binary)).digest('hex'),
    source_sha256: sources.map(name => ({path: name, sha256: crypto.createHash('sha256').update(fs.readFileSync(path.join(root, name))).digest('hex')})),
    cases: results, cleanup, private_tls_files_removed: true,
    boundary: 'Actual owned HTTPS browser/reference pages, shared core authorization, offline signed RS256/JWKS/code and real PostgreSQL commit; no authority setup bypass',
    limitations: ['Google authorization navigation is intercepted only in this owned context; no real Google endpoint contacted',
      'Private certificate trust exception applies only to the owned browser context/proxy; no system/browser settings changed',
      'Offline provider signs controlled public authorization inputs; no real Google eligibility or fresh event evidence',
      'No ordinary server activation, OS default-browser launch, device/Safari recovery resolution or production-readiness claim']};
  if (process.env.EASY_AUTH_GOOGLE_WEB_TEST_REPORT) {
    fs.mkdirSync(path.dirname(process.env.EASY_AUTH_GOOGLE_WEB_TEST_REPORT), {recursive: true});
    fs.writeFileSync(process.env.EASY_AUTH_GOOGLE_WEB_TEST_REPORT, JSON.stringify(report, null, 2) + '\n', {flag: 'wx'});
  }
  console.log(JSON.stringify({passed: results.length, chromium: version, fixture_database_removed: cleanup.database_removed}));
}
main().catch(error => {console.error('Owned Google web suite failed:', error.name, error.caseName || 'fixture', error.infrastructure ? 'owned-provider-infrastructure' : 'acceptance'); process.exitCode = 1;});
