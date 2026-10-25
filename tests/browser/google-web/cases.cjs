'use strict';
const assert = require('node:assert/strict');
const {providerAccount} = require('../reference-ui/provider.cjs');

async function run(browser, origin) {
  const context = await browser.newContext({ignoreHTTPSErrors: true});
  const page = await context.newPage();
  let mode = 'normal', pageErrors = 0, finishes = 0, providerRequests = 0, fixtureFailures = 0;
  const results = [];
  page.on('pageerror', () => {pageErrors++;});
  page.on('request', request => {if (new URL(request.url()).pathname.endsWith('/finish')) finishes++;});
  page.on('response', response => {if (new URL(response.url()).pathname === '/fixture/google/authorize' && response.status() >= 400) fixtureFailures++;});
  await context.route('**/*', async route => {
    const url = new URL(route.request().url());
    if (url.origin === origin) return route.continue();
    if (url.origin === 'https://accounts.google.com') {
      providerRequests++;
      url.searchParams.append('fixture_case', mode);
      return route.fulfill({status: 302, headers: {location: origin + '/fixture/google/authorize?' + url.searchParams.toString()}});
    }
    return route.abort(); // Never contact a real Google or other external endpoint.
  });
  const profile = () => page.evaluate(async () => (await fetch('/v1/session', {cache: 'no-store', credentials: 'same-origin', redirect: 'error'})).status);
  async function privacy() {
    assert.equal(page.url(), origin + '/google/callback', 'callback query/fragment scrubbed');
    const state = await page.evaluate(() => ({cookie: document.cookie, local: localStorage.length, session: sessionStorage.length,
      detail: document.body.textContent.includes('private-owned-provider-detail')}));
    assert.deepEqual(state, {cookie: '', local: 0, session: 0, detail: false});
  }
  async function returned(flow, selected) {
    mode = selected;
    await page.goto(origin + (flow === 'delete' ? '/google/account-delete' : '/google/sign-in'));
    if (flow === 'delete') await page.locator('#confirmation').fill('delete my account');
    await Promise.all([page.waitForURL(url => url.pathname === '/google/callback'), page.locator('#continue').click()]);
    await page.waitForFunction(() => location.search === '' && document.body.textContent.includes('Google returned'));
    await privacy();
  }
  async function finish(flow, status) {
    if (flow === 'delete') await page.locator('#confirmation').fill('delete my account');
    const path = flow === 'delete' ? '/v1/account/google-delete/finish' : '/v1/google/sign-in/finish';
    const response = page.waitForResponse(value => new URL(value.url()).pathname === path);
    await page.locator('#continue').click();
    assert.equal((await response).status(), status);
    await page.waitForFunction(() => !document.getElementById('cancel').disabled);
  }
  async function cancel(flow) {
    const path = flow === 'delete' ? '/v1/account/google-delete/cancel' : '/v1/google/sign-in/cancel';
    const response = page.waitForResponse(value => new URL(value.url()).pathname === path);
    await page.locator('#cancel').click();
    assert.equal((await response).status(), 204);
  }
  async function check(name, action) {
    console.log(JSON.stringify({case: name, status: 'running'}));
    try {await action();} catch (error) {error.caseName = name; error.infrastructure = fixtureFailures > 0; throw error;}
    results.push({name, status: 'passed'});
    console.log(JSON.stringify({case: name, status: 'passed'}));
  }
  try {
    await check('google-provider-denial-bound-cancellation', async () => {await returned('signin', 'denied'); await finish('signin', 401); assert.equal(await profile(), 401);});
    await check('google-provider-failure-is-unavailable', async () => {await returned('signin', 'provider_failure'); await finish('signin', 503); assert.equal(await profile(), 401);});
    await check('google-malformed-return-fixed-page-and-explicit-cancel', async () => {
      mode = 'bad_query'; await page.goto(origin + '/google/sign-in');
      await Promise.all([page.waitForURL(url => url.pathname === '/google/callback'), page.locator('#continue').click()]);
      await page.waitForFunction(() => location.search === '' && document.body.textContent.includes('Return not confirmed'));
      await privacy(); assert.equal(await profile(), 401);
      await page.goto(origin + '/google/sign-in'); await cancel('signin');
    });
    await check('google-restored-page-drops-proof-without-finish', async () => {
      await returned('signin', 'normal'); const before = finishes;
      await page.evaluate(() => {dispatchEvent(new PageTransitionEvent('pagehide', {persisted: true})); dispatchEvent(new PageTransitionEvent('pageshow', {persisted: true}));});
      assert.equal(await page.locator('#confirm-form').isHidden(), true);
      assert.equal(finishes, before); assert.equal(await profile(), 401); await cancel('signin');
    });
    await check('google-client-rejects-and-scrubs-callback-fragment', async () => {
      mode = 'fragment'; await page.goto(origin + '/google/sign-in'); const before = finishes;
      await Promise.all([page.waitForURL(url => url.pathname === '/google/callback'), page.locator('#continue').click()]);
      await page.waitForFunction(() => location.search === '' && location.hash === '' && document.getElementById('status')?.textContent.includes('No usable callback'));
      assert.equal(await page.locator('#confirm-form').isHidden(), true); await privacy();
      assert.equal(finishes, before); assert.equal(await profile(), 401); await cancel('signin');
    });
    await check('google-actual-signed-nonce-rejection', async () => {await returned('signin', 'wrong_nonce'); await finish('signin', 401); assert.equal(await profile(), 401);});
    await check('google-signed-code-commits-session-only-after-confirmation', async () => {
      await returned('signin', 'normal'); assert.equal(await profile(), 401); await finish('signin', 204); assert.equal(await profile(), 200);
      await providerAccount(page, origin, 'https://accounts.google.com', 'oidc');
    });
    await check('google-ambient-session-cannot-switch-account', async () => {
      await page.goto(origin + '/google/sign-in'); const before = providerRequests;
      const response = page.waitForResponse(value => new URL(value.url()).pathname === '/v1/google/sign-in/start');
      await page.locator('#continue').click(); assert.equal((await response).status(), 401);
      assert.equal(providerRequests, before); assert.equal(await profile(), 200);
    });
    await check('google-explicit-deletion-cancel-retains-session', async () => {await returned('delete', 'normal'); assert.equal(await profile(), 200); await cancel('delete'); assert.equal(await profile(), 200);});
    await check('google-deletion-provider-denial-retains-session', async () => {await returned('delete', 'denied'); await finish('delete', 401); assert.equal(await profile(), 200);});
    await check('google-old-signed-time-cannot-delete', async () => {await returned('delete', 'old_time'); await finish('delete', 401); assert.equal(await profile(), 200);});
    await check('google-missing-signed-capability-is-unavailable', async () => {await returned('delete', 'missing_time'); await finish('delete', 503); assert.equal(await profile(), 200);});
    await check('google-fresh-signed-deletion-requires-second-confirmation', async () => {
      await returned('delete', 'normal'); assert.equal(await page.locator('#confirmation').inputValue(), '');
      assert.equal(await profile(), 200); await finish('delete', 204); assert.equal(await profile(), 401);
    });
    assert.equal(pageErrors, 0);
    assert.equal(fixtureFailures, 0, 'owned provider preparation must succeed independently of expected application denials');
    return results;
  } finally {await context.close();}
}
module.exports = {run};
