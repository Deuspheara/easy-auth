'use strict';
const assert = require('node:assert/strict');
const fixtureHttp = require('../apple-web/fixture-http.cjs');
async function open(browser, origin) {
  const context = await browser.newContext({ignoreHTTPSErrors:true});
  const page = await context.newPage();
  let mode='normal', errors=0, violations=0, failures=0, finishes=0;
  const deliveries=[];
  context.on('request',request=>{if(/-link\/finish$/.test(new URL(request.url()).pathname))finishes++;});
  context.on('page', p => {
    p.on('pageerror',()=>{errors++;});
    p.on('console',m=>{if(m.type()==='error' && /content security policy|violates.*directive/i.test(m.text()))violations++;});
    p.on('dialog', d=>d.accept());
  });
  // The first page was created before the observer.
  page.on('pageerror',()=>{errors++;});
  page.on('console',m=>{if(m.type()==='error' && /content security policy|violates.*directive/i.test(m.text()))violations++;});
  page.on('dialog',d=>d.accept());
  await context.route('**/*',async route=>{
    try {
      const request=route.request(), url=new URL(request.url());
      if(url.origin===origin) {
        if(url.pathname==='/apple/callback')deliveries.push({method:request.method(),cookie:(await request.allHeaders()).cookie||''});
        return route.continue();
      }
      const google=url.origin==='https://accounts.google.com' && url.pathname==='/o/oauth2/v2/auth';
      const apple=url.origin==='https://appleid.apple.com' && url.pathname==='/auth/authorize';
      if((google||apple) && request.isNavigationRequest()) {
        url.searchParams.append('fixture_case',mode);
        const path='/fixture/'+(google?'google':'apple')+'/authorize?'+url.searchParams.toString();
        if(google)return route.fulfill({status:302,headers:{location:origin+path}});
        const result=await fixtureHttp.request(origin,path);assert.equal(result.status,200);
        return route.fulfill({status:200,contentType:'text/html',body:result.text});
      }
      return route.abort();
    } catch {failures++;await route.abort().catch(()=>{});}
  });
  async function json(path,target=page) {return target.evaluate(async path=>{
    const response=await fetch(path,{credentials:'same-origin',cache:'no-store',redirect:'error'});
    return {status:response.status,body:response.ok?await response.json():null};
  },path);}
  async function email(target,email) {
    await target.goto(origin+'/');
    await target.locator('#email').fill(email);
    const started=target.waitForResponse(r=>new URL(r.url()).pathname==='/v1/email/start');
    await target.locator('#email-form button[type=submit]').click();assert.equal((await started).status(),202);
    const inbox=await fixtureHttp.request(origin,'/fixture/mail');assert.equal(inbox.status,200);
    const {token}=JSON.parse(inbox.text);assert.equal(typeof token,'string');
    const completed=target.waitForResponse(r=>new URL(r.url()).pathname==='/v1/email/finish');
    await target.goto(origin+'/#token='+encodeURIComponent(token));assert.equal((await completed).status(),204);
    const user=await json('/v1/session',target);assert.equal(user.status,200);return user.body;
  }
  async function accounts(target=page) {
    await target.goto(origin+'/social/accounts');await target.locator('#actions').waitFor({state:'visible'});
  }
  async function returned(provider,selected='normal',target=page) {
    mode=selected;await accounts(target);
    await Promise.all([target.waitForURL(url=>url.pathname===`/${provider}/callback`),target.locator(`[data-link=${provider}]`).click()]);
    await target.locator('#confirm').waitFor({state:'visible'});
    await privacy(provider,target);
  }
  async function finish(provider,expected=204,target=page) {
    const response=target.waitForResponse(r=>new URL(r.url()).pathname===`/v1/account/${provider}-link/finish`);
    await target.locator('#confirm button').click();assert.equal((await response).status(),expected);
    await target.locator('#confirm').waitFor({state:'hidden'});
  }
  async function privacy(provider,target=page) {
    assert.equal(target.url(),origin+`/${provider}/callback`);
    assert.deepEqual(await target.evaluate(()=>({cookie:document.cookie,local:localStorage.length,session:sessionStorage.length,delivery:!!document.getElementById('apple-delivery')})),
      {cookie:'',local:0,session:0,delivery:false});
    if(provider==='apple') assert.deepEqual(deliveries.at(-1),{method:'POST',cookie:''});
  }
  async function cancel(provider,target=page) {
    const response=target.waitForResponse(r=>new URL(r.url()).pathname===`/v1/account/${provider}-link/cancel`);
    await target.locator('#cancel').click();assert.equal((await response).status(),204);
  }
  return {context,page,json,email,accounts,returned,finish,privacy,cancel,
    mode:value=>{mode=value;},counters:()=>({errors,violations,failures,finishes}),close:()=>context.close()};
}
module.exports={open};
