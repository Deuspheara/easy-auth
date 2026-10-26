'use strict';
const assert = require('node:assert/strict');
const fs = require('node:fs');
const http = require('node:http');
const path = require('node:path');
const {execFileSync} = require('node:child_process');
const {chromium} = require('../passkeys/node_modules/playwright');
const {mailbox} = require('./mail.cjs');
const root = path.resolve(__dirname, '../../..');

function localOrigin(name) {
  const url = new URL(process.env[name]);
  assert.equal(url.protocol, 'http:');
  assert.equal(url.hostname, '127.0.0.1');
  assert.equal(url.pathname + url.search + url.hash, '/');
  assert.equal(url.username + url.password, '');
  return url.origin;
}
function rustProbe(origin) {
  const output = execFileSync(path.join(root, 'target/debug/easy-auth-http-probe-example'), [], {
    cwd: root, env: {...process.env, EASY_AUTH_CLIENT_ORIGIN: origin},
    timeout: 30000, stdio: ['ignore', 'pipe', 'pipe'],
  });
  assert.deepEqual(JSON.parse(output), {health: 200, ready: 200, anonymous_session: 401});
}
async function wrongHostRefused(origin) {
  assert.equal((await fetch(origin + '/readyz', {signal: AbortSignal.timeout(5000)})).status, 200);
  await new Promise((resolve, reject) => {
    const request = http.request(new URL('/readyz', origin), {headers: {Host: 'untrusted.example'}});
    request.on('response', response => { response.resume(); reject(new Error('unexpected wrong-host response')); });
    request.on('error', error => error.code === 'ECONNRESET' ? resolve() : reject(error));
    request.setTimeout(5000, () => request.destroy(new Error('wrong-host deadline')));
    request.end();
  });
  assert.equal((await fetch(origin + '/readyz', {signal: AbortSignal.timeout(5000)})).status, 200);
}
async function ownedPage(browser, origin) {
  const context = await browser.newContext();
  const page = await context.newPage();
  const counts = {external: 0, errors: 0};
  page.on('pageerror', () => counts.errors++);
  await context.route('**/*', async route => {
    const url = new URL(route.request().url());
    if (url.origin !== origin) { counts.external++; return route.abort(); }
    if (url.pathname === '/owned-client.js' && route.request().method() === 'GET') {
      return route.fulfill({status: 200, contentType: 'text/javascript',
        body: fs.readFileSync(path.join(root, 'target/client-example/browser.js'), 'utf8')});
    }
    return route.continue();
  });
  return {context, page, counts};
}
async function journey(browser, origin, mail) {
  const {context, page, counts} = await ownedPage(browser, origin);
  let stage = 'anonymous-clients';
  try {
    await page.goto(origin);
    assert.equal(await page.evaluate(async () => (await import('/owned-client.js')).currentUser()), null);
    rustProbe(origin);
    stage = 'origin-refusal';
    const refused = await fetch(origin + '/v1/email/start', {method: 'POST', signal: AbortSignal.timeout(5000),
      headers: {'Content-Type': 'application/json'}, body: JSON.stringify({email: mail.recipient})});
    assert.equal(refused.status, 403);
    stage = 'proxy-host-and-body-boundary';
    await wrongHostRefused(origin);
    const oversized = await fetch(origin + '/v1/email/start', {method: 'POST', signal: AbortSignal.timeout(5000),
      headers: {Origin: origin, 'Content-Type': 'application/json'}, body: JSON.stringify({email: 'x'.repeat(9000)})});
    assert.equal(oversized.status, 413);
    assert.equal(await mail.count(), 0);
    stage = 'actual-mailbox-signin';
    assert.equal(await page.evaluate(async email => (await import('/owned-client.js')).requestEmail(email), mail.recipient), 'accepted');
    await page.goto(await mail.link());
    await page.locator('#account').waitFor({state: 'visible'});
    const actual = await page.evaluate(async () => (await import('/owned-client.js')).currentUser());
    assert.equal(actual.email, mail.recipient);
    assert.equal(actual.authentication_policy, 'mailbox');
    assert.equal(await page.evaluate(() => location.hash), '');
    stage = 'independent-rust-remains-anonymous';
    rustProbe(origin);
    stage = 'actual-logout';
    await page.evaluate(async () => (await import('/owned-client.js')).signOut());
    assert.equal(await page.evaluate(async () => (await import('/owned-client.js')).currentUser()), null);
    assert.equal(counts.external, 0);
    assert.equal(counts.errors, 0);
    return counts;
  } catch (error) { error.stageName = stage; throw error; }
  finally { await context.close(); }
}
async function main() {
  const origin = localOrigin('EASY_AUTH_CONTAINER_ORIGIN');
  const mail = mailbox(localOrigin('EASY_AUTH_CONTAINER_MAIL_ORIGIN'), origin);
  let browser, failure, counts, removed;
  try {
    browser = await chromium.launch({headless: true});
    counts = await journey(browser, origin, mail);
  } catch (error) { failure = {stage: error.stageName || 'browser-startup', category: error.name}; }
  finally {
    for (const action of [async () => { if (browser) await browser.close(); }, async () => { removed = await mail.cleanup(); }]) {
      try { await action(); } catch (error) { failure ||= {stage: 'owned-cleanup', category: error.name}; }
    }
  }
  if (failure) {
    console.error(JSON.stringify({suite: 'container-clients', status: 'failed', ...failure}));
    process.exitCode = 1;
    return;
  }
  assert.equal(removed, 1);
  console.log(JSON.stringify({suite: 'container-clients', status: 'passed',
    rust_independent: true, typescript_actual_session: true, actual_smtp: true,
    origin_refusal: true, wrong_host_refused: true, oversized_body_refused: true,
    logout_revoked: true, owned_messages_removed: removed,
    external_requests: counts.external, browser_errors: counts.errors}));
}
main().catch(error => {console.error(JSON.stringify({suite: 'container-clients', status: 'failed', category: error.name}));process.exitCode = 1;});
