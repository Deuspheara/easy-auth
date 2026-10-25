'use strict';
const assert = require('node:assert/strict');
const fixtureHttp = require('./fixture-http.cjs');

// Every result is produced through the public authorization URL, maintained JOSE
// fixture and actual core/PG completion. No proof/session setup endpoint exists.
async function open(browser, origin) {
  const context = await browser.newContext({ignoreHTTPSErrors: true});
  const page = await context.newPage();
  let mode = 'normal', arrivalCookie = null, finishes = 0, callbackPosts = 0, providerRequests = 0, errors = 0, fixtureFailures=0, cspViolations=0;
  const deliveries = [];
  page.on('pageerror', () => {errors++;});
  page.on('console',message=>{if(message.type()==='error' && /content security policy|violates.*directive/i.test(message.text()))cspViolations++;});
  await context.route('**/*', async route => {
    try {
    const request = route.request(), url = new URL(request.url());
    if (url.origin === origin) {
      if (url.pathname === '/v1/apple/sign-in/finish') finishes++;
      if (url.pathname === '/apple/callback') {
        callbackPosts++;
        const headers = await request.allHeaders();
        deliveries.push({method: request.method(), cookie: headers.cookie || '', body: request.postData()});
      }
      return route.continue();
    }
    if (url.origin === 'https://appleid.apple.com' && url.pathname === '/auth/authorize' && request.isNavigationRequest()) {
      providerRequests++;
      url.searchParams.append('fixture_case', mode);
      const response = await fixtureHttp.request(origin, '/fixture/apple/authorize?' + url.searchParams.toString());
      assert.equal(response.status, 200, 'owned provider input preparation must succeed');
      if (arrivalCookie) await context.addCookies([arrivalCookie]);
      return route.fulfill({status: 200, contentType: 'text/html', body: response.text});
    }
    return route.abort();
    } catch {fixtureFailures++;await route.abort().catch(()=>{});}
  });
  const profile = () => page.evaluate(async () => (await fetch('/v1/session', {cache:'no-store', credentials:'same-origin'})).status);
  const facts = async () => {
    const response = await fixtureHttp.request(origin, '/fixture/apple/facts');
    assert.equal(response.status, 200); return JSON.parse(response.text);
  };
  async function privacy() {
    assert.equal(page.url(), origin + '/apple/callback');
    assert.deepEqual(await page.evaluate(() => ({cookie:document.cookie,local:localStorage.length,session:sessionStorage.length,template:!!document.getElementById('apple-delivery'),xss:globalThis.ownedXss===true})),
      {cookie:'',local:0,session:0,template:false,xss:false});
    const last=deliveries.at(-1);
    assert.equal(last.method,'POST'); assert.equal(last.cookie,'','Lax proofs and session are absent on actual cross-site POST');
    assert.equal(await page.locator('body').textContent().then(text=>text.includes('unsigned@example.com')||text.includes('ownedXss')),false);
  }
  async function returned(selected='normal') {
    mode=selected;
    await page.goto(origin+'/apple/sign-in');
    await Promise.all([page.waitForURL(url=>url.pathname==='/apple/callback'),page.locator('#continue').click()]);
    if(selected!=='bad_form') {
      await page.waitForFunction(()=>!document.getElementById('confirm')?.hidden);
      await privacy();
    }
  }
  async function finish(expected) {
    const response=page.waitForResponse(r=>new URL(r.url()).pathname==='/v1/apple/sign-in/finish');
    await page.locator('#continue').click(); assert.equal((await response).status(),expected);
    await page.waitForFunction(()=>document.getElementById('confirm').hidden);
  }
  async function cancel() {
    const response=page.waitForResponse(r=>new URL(r.url()).pathname==='/v1/apple/sign-in/cancel');
    await page.locator('#cancel').click(); assert.equal((await response).status(),204);
  }
  async function clean() {await page.goto(origin+'/apple/sign-in'); await cancel();}
  return {context,page,profile,facts,returned,finish,cancel,clean,privacy,deliveries,
    counters:()=>({finishes,callbackPosts,providerRequests,errors,fixtureFailures,cspViolations}),arrival:cookie=>{arrivalCookie=cookie;},close:()=>context.close()};
}
module.exports={open};
