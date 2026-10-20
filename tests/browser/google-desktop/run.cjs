'use strict';
const assert = require('node:assert/strict');
const {spawn, execFileSync} = require('node:child_process');
const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');
const readline = require('node:readline');
const {chromium} = require('../passkeys/node_modules/playwright');
const root = path.resolve(__dirname, '../../..');

async function main() {
  const binary = process.env.EASY_AUTH_DESKTOP_TEST_BINARY || path.join(root, 'target/debug/examples/google-desktop-browser');
  const child = spawn(binary, [], {cwd: root, stdio: ['ignore', 'pipe', 'pipe']});
  let resolveReady, rejectReady, received = false, diagnostic = false, failure, browser;
  const ready = new Promise((resolve, reject) => {resolveReady = resolve; rejectReady = reject;});
  const lines = readline.createInterface({input: child.stdout});
  lines.on('line', line => {
    try { const value = JSON.parse(line); if (value.return_url) resolveReady(value.return_url); if (value.received === true) received = true; }
    catch {rejectReady(new Error('owned fixture IPC invalid'));}
  });
  child.stderr.on('data', () => {diagnostic = true;});
  child.on('error', () => rejectReady(new Error('owned fixture could not start')));
  const exited = new Promise(resolve => child.on('close', code => {rejectReady(new Error('owned fixture ended')); resolve(code);}));
  const timeout = setTimeout(() => {failure = new Error('owned browser timeout'); child.kill('SIGKILL'); rejectReady(failure);}, 45000);
  let version;
  try {
    const destination = new URL(await ready);
    assert.equal(destination.hostname, '127.0.0.1');
    assert.equal(destination.pathname, '/owned-return');
    browser = await chromium.launch({headless: true});
    version = browser.version();
    const context = await browser.newContext();
    const page = await context.newPage();
    let pageErrors = 0, external = false;
    page.on('pageerror', () => {pageErrors += 1;});
    await context.route('**/*', route => {
      if (new URL(route.request().url()).origin !== destination.origin) {external = true; return route.abort();}
      return route.continue();
    });
    const response = await page.goto(destination.href, {waitUntil: 'load'});
    assert.equal(response.status(), 200);
    await page.waitForFunction(() => location.search === '' && location.hash === '');
    assert.equal(new URL(page.url()).pathname, '/owned-return');
    const headers = response.headers();
    assert.equal(headers['cache-control'], 'no-store');
    assert.equal(headers['referrer-policy'], 'no-referrer');
    assert.equal(headers['set-cookie'], undefined);
    const html = await page.content();
    const script = html.match(/<script>([^<]+)<\/script>/)[1];
    const digest = crypto.createHash('sha256').update(script).digest('base64');
    assert.equal(headers['content-security-policy'].includes(`'sha256-${digest}'`), true);
    assert.equal(html.includes('owned-browser-code'), false);
    assert.equal(html.includes(destination.searchParams.get('state')), false);
    assert.equal((await context.cookies()).length, 0);
    assert.deepEqual(await page.evaluate(() => ({local: localStorage.length, session: sessionStorage.length})), {local: 0, session: 0});
    assert.equal(pageErrors, 0);
    assert.equal(external, false);
    assert.equal(await exited, 0);
    assert.equal(received, true);
    assert.equal(diagnostic, false);
    if (failure) throw failure;
  } finally {
    clearTimeout(timeout);
    await browser?.close();
    if (child.exitCode === null && child.signalCode === null) child.kill('SIGKILL');
    await exited;
    lines.close();
  }
  const sources = execFileSync('git', ['ls-files', '--cached', '--others', '--exclude-standard', '-z'], {cwd: root})
    .toString().split('\0').filter(name => name && !name.includes('/results/') &&
      (/\.(rs|sql|toml|cjs|js|html|json|yml|yaml)$/.test(name) || name === 'Cargo.lock'));
  const report = {recorded_at: new Date().toISOString(), node: process.version,
    playwright: require('../passkeys/node_modules/playwright/package.json').version, chromium: version,
    platform: process.platform, arch: process.arch,
    source_base_revision: execFileSync('git', ['rev-parse', 'HEAD'], {cwd: root}).toString().trim(),
    fixture_binary_sha256: crypto.createHash('sha256').update(fs.readFileSync(binary)).digest('hex'),
    source_sha256: sources.map(name => ({path: name, sha256: crypto.createHash('sha256').update(fs.readFileSync(path.join(root, name))).digest('hex')})),
    cases: [{name:'actual-owned-loopback-browser-return', status:'passed', actual_socket: true, opaque_delivery_received: true,
      query_scrubbed_by_csp_allowed_script: true, no_cookies_or_script_storage: true, proof_not_reflected: true}],
    limits: 'Owned Chromium/socket transport only; no Google, native registered client, OS browser launch, database identity/session or mobile evidence'};
  if (process.env.EASY_AUTH_DESKTOP_TEST_REPORT) fs.writeFileSync(process.env.EASY_AUTH_DESKTOP_TEST_REPORT, JSON.stringify(report, null, 2) + '\n', {flag: 'wx'});
  console.log(JSON.stringify({passed: 1, chromium: version, fixture_exit: 0}));
}
main().catch(error => {console.error('Desktop browser suite failed:', error.name); process.exitCode = 1;});
