'use strict';
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const {chromium} = require('../passkeys/node_modules/playwright');

// Fixed-client behavior only: intercepted HTTPS is not signed-provider acceptance.
async function main() {
  const directory = path.resolve(__dirname, '../../../crates/auth-axum/src/oidc/web');
  const browser = await chromium.launch({headless:true});
  const context = await browser.newContext();
  const page = await context.newPage();
  const calls = [];
  let finishStatus = 204;
  let errors = 0;
  page.on('pageerror', () => errors++);
  const headers = {'cache-control':'no-store','referrer-policy':'no-referrer',
    'content-security-policy':"default-src 'none'; script-src 'self'; connect-src 'self'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'"};
  await context.route('https://app.example/**', async route => {
    const request = route.request();
    const url = new URL(request.url());
    if (request.method() === 'POST') {
      calls.push({action:url.pathname.split('/').at(-1), body:JSON.parse(request.postData())});
      const status = url.pathname.endsWith('/finish') ? finishStatus : 204;
      await route.fulfill({status, headers, ...(status === 204 ? {} : {contentType:'application/json',body:JSON.stringify({code:'temporarily_unavailable',detail:'secret-server-marker'})})});
      return;
    }
    const file = url.pathname.endsWith('callback-error.js') ? 'error.js'
      : url.pathname.endsWith('.js') ? 'signin.js' : url.pathname.endsWith('/error') ? 'error.html' : 'signin.html';
    await route.fulfill({status:200,headers,contentType:file.endsWith('.js')?'text/javascript':'text/html',body:fs.readFileSync(path.join(directory,file),'utf8')});
  });
  const callback = 'https://app.example/oidc/callback';
  const state = 'A'.repeat(43);
  const query = new URLSearchParams({state,code:'owned-client-code',iss:'https://issuer.example'}).toString();
  let negatives=0;
  try {
    for (const suffix of ['', '?error=access_denied&error_description=secret-provider-marker', '?'+query+'&state='+state,
      '?'+query+'&owner=secret-provider-marker', '?'+query+'#secret-provider-marker', '?'+query+'&session_state=%oops', '?'+query+'&session_state='+'x'.repeat(8200)]) {
      await page.goto(callback+suffix);
      await page.waitForFunction(() => document.getElementById('status').textContent.startsWith('No usable callback'));
      assert.equal(page.url(),callback);
      assert.equal(await page.locator('#signin-form').isHidden(),true);
      assert.equal((await page.locator('body').innerText()).includes('secret-provider-marker'),false);
      assert.equal(calls.length,0);
      negatives++;
    }
    await page.goto(callback+'?'+query);
    await page.waitForFunction(() => !document.getElementById('signin-form').hidden);
    assert.equal(page.url(),callback);assert.equal(calls.length,0,'callback must not automatically finish');
    await page.locator('#continue').click();
    await page.waitForFunction(() => document.getElementById('status').textContent.startsWith('Provider sign-in completed.'));
    assert.deepEqual(calls,[{action:'finish',body:{state,code:'owned-client-code',issuer:'https://issuer.example'}}]);
    assert.equal(await page.locator('#signin-form').isHidden(),true);
    await page.reload();
    await page.waitForFunction(() => document.getElementById('status').textContent.startsWith('No usable callback'));
    assert.equal(calls.length,1,'reload cannot replay scrubbed proof');
    await page.locator('#cancel').click();
    await page.waitForFunction(() => document.getElementById('status').textContent.startsWith('Pending sign-in cancelled.'));
    assert.deepEqual(calls[1],{action:'cancel',body:{}});
    finishStatus=503;
    await page.goto(callback+'?'+query);
    await page.waitForFunction(() => !document.getElementById('signin-form').hidden);
    await page.locator('#continue').click();
    await page.waitForFunction(() => document.getElementById('status').textContent.startsWith('The operation was not confirmed.'));
    assert.equal(await page.locator('#signin-form').isHidden(),true);
    assert.equal((await page.locator('body').innerText()).includes('secret-server-marker'),false);
    const count=calls.length;
    await page.goto(callback+'?'+query);
    await page.waitForFunction(() => !document.getElementById('signin-form').hidden);
    await page.evaluate(() => {
      window.dispatchEvent(new PageTransitionEvent('pagehide',{persisted:true}));
      window.dispatchEvent(new PageTransitionEvent('pageshow',{persisted:true}));
    });
    await page.waitForFunction(() => document.getElementById('status').textContent.startsWith('Page restored without callback proof.'));
    assert.equal(await page.locator('#signin-form').isHidden(),true);assert.equal(calls.length,count);
    await page.goto('https://app.example/oidc/sign-in?'+query);
    await page.waitForFunction(() => document.getElementById('status').textContent.startsWith('Continue to your configured provider.'));
    assert.equal(page.url(),'https://app.example/oidc/sign-in');
    assert.equal(calls.length,count,'ordinary sign-in page cannot import URL proof');
    await page.goto('https://app.example/oidc/error?secret-provider-marker#secret-fragment');
    await page.waitForFunction(() => !location.search && !location.hash);
    assert.equal((await page.locator('body').innerText()).includes('secret-provider-marker'),false);
    assert.equal(await page.evaluate(() => localStorage.length+sessionStorage.length),0);
    assert.equal(errors,0);
    console.log(JSON.stringify({suite:'oidc-signin-reference-client',status:'passed',malformed_callback_cases:negatives,
      explicit_finish:true,url_scrubbed:true,reload_cannot_replay:true,cancellation_posts_empty_closed_body:true,
      unavailable_is_not_success:true,no_browser_storage:true,navigation_drops_proof:true,ordinary_page_cannot_import_proof:true,
      actual_provider_acceptance:false}));
  } finally {await browser.close();}
}
main().catch(() => {console.error('OIDC sign-in reference-client checks failed');process.exitCode=1;});
