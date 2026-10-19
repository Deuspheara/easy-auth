'use strict';
const assert = require('node:assert/strict');
const crypto = require('node:crypto');

async function callback(browser, authorization, provider, redirect, mutation) {
  const url = new URL(authorization);
  if (mutation==='nonce') url.searchParams.set('nonce',crypto.randomBytes(32).toString('base64url'));
  if (mutation==='pkce') url.searchParams.set('code_challenge',crypto.randomBytes(32).toString('base64url'));
  assert.equal(url.origin,new URL(provider.issuer).origin);
  const context=await browser.newContext({ignoreHTTPSErrors:true});
  let captured,unexpected=0,pageErrors=0;
  let stage='provider_navigation',page;
  const received=new Promise(resolve=>{captured=resolve;});
  try {
    await context.route('**/*',async route=>{
      const target=new URL(route.request().url());
      const base=new URL(target);base.search='';
      if (base.href===redirect) {
        captured(target.href);
        await route.fulfill({status:200,contentType:'text/html',body:'<!doctype html><title>Owned callback captured</title>'});
      } else if (target.origin===url.origin) await route.continue();
      else {unexpected+=1;await route.abort();}
    });
    page=await context.newPage();
    page.on('pageerror',()=>{pageErrors+=1;});
    page.on('request',request=>{
      const target=new URL(request.url());
      const base=new URL(target);base.search='';
      if(base.href===redirect)captured(target.href);
    });
    page.on('requestfailed',request=>{
      const failure=request.failure()?.errorText;
      const code=['net::ERR_CERT_AUTHORITY_INVALID','net::ERR_CONNECTION_REFUSED','net::ERR_NAME_NOT_RESOLVED','net::ERR_FAILED','net::ERR_ABORTED'].includes(failure)?failure:'other';
      console.log(JSON.stringify({browser_request_failure:code}));
    });
    await page.goto(url.href,{waitUntil:'domcontentloaded',timeout:15000});
    stage='provider_username';
    await page.locator('#username').fill(provider.username);
    stage='provider_password';
    await page.locator('#password').fill(provider.password);
    stage='provider_submit';
    await page.locator('#kc-login').click();
    stage='provider_callback';
    const result=await Promise.race([received,new Promise((_,reject)=>{
      const timer=setTimeout(()=>reject(new Error('owned callback timeout')),15000);timer.unref();
    })]);
    assert.equal(unexpected,0,'browser may contact only the owned provider and intercepted callback');
    assert.equal(pageErrors,0,'working provider browser fixture');
    return result;
  } catch(error) {
    const facts=page?await page.evaluate(()=>({
      login_form:!!document.querySelector('#kc-form-login'),
      profile_form:!!document.querySelector('#kc-update-profile-form,#kc-register-form'),
      password_update:!!document.querySelector('#password-new'),
      email_action:!!document.querySelector('#kc-verify-email-form'),
      error_feedback:!!document.querySelector('#input-error,.kc-feedback-text'),
      required_action:location.pathname.includes('/login-actions/required-action'),
      authentication_action:location.pathname.includes('/login-actions/authenticate'),
      forms:document.forms.length,
      callback_title:document.title==='Owned callback captured',
      error_page:!!document.querySelector('#kc-error-message'),
      login_action:location.pathname.includes('/login-actions/'),
      authorization_page:location.pathname.endsWith('/protocol/openid-connect/auth')
    })).catch(()=>({page_unavailable:true})):{};
    const locationFacts=page?{provider_origin:new URL(page.url()).origin===url.origin,
      callback_origin:new URL(page.url()).origin===new URL(redirect).origin}:{};
    console.log(JSON.stringify({browser_fixture_diagnostic:{stage,unexpected,pageErrors,...locationFacts,...facts}}));
    error.stageName=stage;throw error;
  }
  finally {await context.close();}
}
module.exports={callback};
