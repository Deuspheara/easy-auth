'use strict';
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const {chromium} = require('../passkeys/node_modules/playwright');

// Reference-client checks with controlled HTTP responses, separate from actual
// Keycloak/PostgreSQL acceptance. No external provider, credential or account.
async function main() {
  const directory = path.resolve(__dirname, '../../../crates/auth-axum/src/oidc/deletion');
  const html = fs.readFileSync(path.join(directory, 'pages.html'), 'utf8');
  const script = fs.readFileSync(path.join(directory, 'pages.js'), 'utf8');
  const browser = await chromium.launch({headless:true});
  const context = await browser.newContext();
  const page = await context.newPage();
  const calls = [];
  let finishStatus = 204;
  let pageErrors = 0;
  page.on('pageerror', () => pageErrors++);
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
    await route.fulfill({status:200,headers,contentType:url.pathname.endsWith('.js')?'text/javascript':'text/html',body:url.pathname.endsWith('.js')?script:html});
  });
  const callback = 'https://app.example/oidc/account-delete/callback';
  const state = 'A'.repeat(43);
  const query = new URLSearchParams({state,code:'owned-client-code',iss:'https://issuer.example'}).toString();
  let negativeCases = 0;
  try {
    for (const suffix of ['', '?error=access_denied&error_description=secret-provider-marker', '?'+query+'&state='+state,
      '?'+query+'&owner=secret-provider-marker', '?'+query+'#secret-provider-marker', '?'+query+'&session_state=%oops', '?'+query+'&session_state='+'x'.repeat(8200)]) {
      await page.goto(callback+suffix);
      await page.waitForFunction(() => document.getElementById('status').textContent.startsWith('No usable callback'));
      assert.equal(page.url(), callback, 'callback URL must be scrubbed');
      assert.equal(await page.locator('#confirm-form').isHidden(),true);
      assert.equal((await page.locator('body').innerText()).includes('secret-provider-marker'),false);
      assert.equal(calls.length,0,'callback GET must not automatically POST');
      negativeCases++;
    }
    await page.goto(callback+'?'+query);
    await page.waitForFunction(() => !document.getElementById('confirm-form').hidden);
    assert.equal(page.url(),callback); assert.equal(calls.length,0);
    await page.locator('#confirmation').fill('yes');
    await page.locator('#confirm').click();
    assert.equal(calls.length,0,'destructive confirmation is required');
    await page.locator('#confirmation').fill('delete my account');
    await page.locator('#confirm').click();
    await page.waitForFunction(() => document.getElementById('status').textContent.startsWith('Account deletion completed.'));
    assert.equal(calls.length,1);
    assert.deepEqual(calls[0],{action:'finish',body:{confirmation:'delete my account',state,code:'owned-client-code',issuer:'https://issuer.example'}});
    assert.equal(await page.locator('#confirmation').inputValue(),'');
    await page.reload();
    await page.waitForFunction(() => document.getElementById('status').textContent.startsWith('No usable callback'));
    assert.equal(calls.length,1,'reload cannot replay scrubbed proof');
    await page.locator('#cancel').click();
    await page.waitForFunction(() => document.getElementById('status').textContent.startsWith('Pending deletion cancelled.'));
    assert.deepEqual(calls[1],{action:'cancel',body:{}});
    finishStatus = 503;
    await page.goto(callback+'?'+query);
    await page.waitForFunction(() => !document.getElementById('confirm-form').hidden);
    await page.locator('#confirmation').fill('delete my account');
    await page.locator('#confirm').click();
    await page.waitForFunction(() => document.getElementById('status').textContent.startsWith('The operation was not confirmed.'));
    assert.equal((await page.locator('body').innerText()).includes('secret-server-marker'),false);
    assert.equal(await page.locator('#confirm-form').isHidden(),true);
    assert.equal(await page.evaluate(() => localStorage.length+sessionStorage.length),0);
    assert.equal(pageErrors,0);
    console.log(JSON.stringify({suite:'oidc-deletion-reference-client',status:'passed',malformed_callback_cases:negativeCases,
      explicit_confirmation:true,url_scrubbed:true,reload_cannot_replay:true,cancellation_denial_only:true,
      unavailable_is_not_success:true,no_browser_storage:true,actual_provider_acceptance:false}));
  } finally {await browser.close();}
}
main().catch(() => {console.error('OIDC deletion reference-client checks failed');process.exitCode=1;});
