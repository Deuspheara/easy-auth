'use strict';
const assert = require('node:assert/strict');
async function run(browser,origin) {
  const context = await browser.newContext({ignoreHTTPSErrors:true});
  const page = await context.newPage();
  let prepares = 0, decisions = 0, errors = 0, captured = null, passed = 0;
  page.on('pageerror',() => { errors++; });
  context.on('request',request => {
    const path = new URL(request.url()).pathname;
    if (path === '/v1/oidc/consent/prepare') prepares++;
    if (/\/consent\/(approve|cancel)$/.test(path)) decisions++;
  });
  await context.route('**/*',async route => {
    const url = new URL(route.request().url());
    if (url.origin === origin) return route.continue();
    if (url.origin === 'https://client.example' && url.pathname === '/callback') {
      captured = url;
      return route.fulfill({status:200,headers:{'Cache-Control':'no-store','Referrer-Policy':'no-referrer'},contentType:'text/html',body:'<!doctype html><title>Owned application callback</title>'});
    }
    return route.abort();
  });
  async function check(name,action) {
    try { await action(); } catch (error) { error.caseName = name; throw error; }
    passed++;
  }
  async function post(path,body) {
    return page.evaluate(async ({path,body}) => (await fetch(path,{method:'POST',credentials:'same-origin',headers:{'Content-Type':'application/json'},body:JSON.stringify(body)})).status,{path,body});
  }
  try {
    await page.goto(origin + '/');
    assert.equal(await post('/v1/email/start',{email:'owner@example.test'}),202);
    // Actual delivery from the owned inbox; no private proof cookie is read or
    // manufactured, and normal HTTP email completion establishes the session.
    const completed = await page.evaluate(async () => {
      const {token} = await (await fetch('/fixture/mail')).json();
      return (await fetch('/v1/email/finish',{method:'POST',credentials:'same-origin',headers:{'Content-Type':'application/json'},body:JSON.stringify({token})})).status;
    });
    assert.equal(completed,204);
    const publicInput = await page.evaluate(async () => (await fetch('/fixture/issuer/public')).json());
    function authorization(state='client-state') {
      const query = new URLSearchParams({client_id:publicInput.client_id,response_type:'code',redirect_uri:'https://client.example/callback',scope:'openid',state,nonce:'client-nonce',code_challenge:publicInput.challenge,code_challenge_method:'S256'});
      return origin + '/oidc/authorize?' + query;
    }
    async function returned() {
      await page.goto(authorization());
      await page.waitForFunction(() => location.search === '' && document.getElementById('prepare'));
    }
    async function prepare(target = page) {
      const response = target.waitForResponse(r => new URL(r.url()).pathname === '/v1/oidc/consent/prepare');
      await target.locator('#prepare').click();
      const received = await response; assert.equal(received.status(),200);
      const preview = await received.json();
      await target.locator('#preview').waitFor({state:'visible'});
      return preview;
    }
    await check('get-only-scrubs-query-without-preparing',async () => {
      await returned();assert.equal(prepares,0);assert.equal(decisions,0);
      const privacy = await page.evaluate(() => ({cookie:document.cookie,local:localStorage.length,session:sessionStorage.length}));
      assert.deepEqual(privacy,{cookie:'',local:0,session:0});
    });
    await check('explicit-preview-keeps-secrets-private-and-waits-for-consent',async () => {
      await prepare();assert.equal(prepares,1);assert.equal(decisions,0);
      assert.equal(await page.locator('#client').textContent(),publicInput.client_id);
      assert.equal(await page.locator('#destination').textContent(),'https://client.example/callback');
      assert.equal(await page.evaluate(() => document.cookie),'');
    });
    await check('reload-resumes-only-a-protected-preview',async () => {
      const before = decisions;
      await page.reload();
      const response = page.waitForResponse(r => new URL(r.url()).pathname === '/v1/oidc/consent/resume');
      await page.locator('#resume').click();assert.equal((await response).status(),200);
      await page.locator('#preview').waitFor({state:'visible'});
      assert.equal(decisions,before);assert.equal(await page.locator('#client').textContent(),publicInput.client_id);
    });
    await check('explicit-denial-returns-only-bound-error',async () => {
      await Promise.all([page.waitForURL(url => url.hostname === 'client.example'),page.locator('#cancel').click()]);
      assert.equal(captured.searchParams.get('error'),'access_denied');assert.equal(captured.searchParams.has('code'),false);
      assert.equal(captured.searchParams.get('state'),'client-state');assert.equal(captured.searchParams.get('iss'),origin);
    });
    await check('approval-returns-one-code-without-replacing-local-session',async () => {
      await returned();await prepare();
      await Promise.all([page.waitForURL(url => url.hostname === 'client.example'),page.locator('#approve').click()]);
      assert.match(captured.searchParams.get('code'),/^[A-Za-z0-9_-]{43}$/);
      assert.equal(captured.searchParams.get('state'),'client-state');assert.equal(captured.searchParams.get('iss'),origin);
      await page.goto(origin + '/');
      assert.equal(await page.evaluate(async () => (await fetch('/v1/session')).status),200);
    });
    await check('old-tab-selector-cannot-approve-new-private-cookie-operation',async () => {
      await returned();const oldPreview = await prepare();
      // Cancel through the real protected endpoint while leaving the old tab's
      // in-memory preview intact, then prepare a new operation in another tab.
      assert.equal(await post('/v1/oidc/consent/cancel',{authorization:oldPreview.authorization}),200);
      const newer = await context.newPage();await newer.goto(authorization('other-state'));
      await prepare(newer);
      const refused = page.waitForResponse(r => new URL(r.url()).pathname === '/v1/oidc/consent/approve');
      await page.locator('#approve').click();assert.equal((await refused).status(),401);
      await Promise.all([newer.waitForURL(url => url.hostname === 'client.example'),newer.locator('#approve').click()]);
      assert.equal(captured.searchParams.get('state'),'other-state');await newer.close();
    });
    await check('restored-page-drops-input-and-sends-no-decision',async () => {
      await returned();const before = decisions;
      await page.evaluate(() => {dispatchEvent(new PageTransitionEvent('pagehide',{persisted:true}));dispatchEvent(new PageTransitionEvent('pageshow',{persisted:true}));});
      assert.equal(await page.locator('#prepare').isDisabled(),true);assert.equal(decisions,before);
    });
    await check('duplicate-query-member-refuses-preparation-and-scrubs-fragment',async () => {
      const before = prepares;
      await page.goto(authorization() + '&state=duplicate#ignored');
      await page.waitForFunction(() => location.search === '' && location.hash === '');
      assert.equal(await page.locator('#prepare').isDisabled(),true);assert.equal(prepares,before);
    });
    assert.equal(errors,0);
    return passed;
  } finally { await context.close(); }
}
module.exports = {run};
