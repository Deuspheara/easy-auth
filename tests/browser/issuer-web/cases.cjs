'use strict';
const assert = require('node:assert/strict');
async function run(browser,origin,actor) {
  const context=await browser.newContext({ignoreHTTPSErrors:true});
  const page=await context.newPage();
  let callback,code,id,tokens,prepares=0,decisions=0,errors=0,passed=0;
  page.on('pageerror',() => {errors++;});
  context.on('request',request => {
    const path=new URL(request.url()).pathname;
    if(path==='/v1/oidc/consent/prepare')prepares++;
    if(path==='/v1/oidc/consent/approve')decisions++;
  });
  await context.route('**/*',async route => {
    const url=new URL(route.request().url());
    if(url.origin===origin)return route.continue();
    if(url.origin==='https://client.example' && url.pathname==='/callback') {
      callback=url;
      return route.fulfill({status:200,headers:{'Cache-Control':'no-store','Referrer-Policy':'no-referrer'},contentType:'text/html',body:'<!doctype html><title>Owned application callback</title>'});
    }
    return route.abort();
  });
  async function check(name,action) {
    try {await action();}catch(error){error.caseName=name;throw error;}passed++;
  }
  try {
    await check('actual-email-and-explicit-browser-consent-return-bound-client-code',async () => {
      await page.goto(origin+'/');
      const completed=await page.evaluate(async () => {
        const post=(path,body) => fetch(path,{method:'POST',credentials:'same-origin',headers:{'Content-Type':'application/json'},body:JSON.stringify(body)});
        if((await post('/v1/email/start',{email:'owner@example.test'})).status!==202)return false;
        const {token}=await (await fetch('/fixture/mail')).json();
        return (await post('/v1/email/finish',{token})).status===204;
      });
      assert.equal(completed,true);
      id=(await actor.request('/fixture/issuer/public')).value.client_id;
      const query=new URLSearchParams({client_id:id,response_type:'code',redirect_uri:'https://client.example/callback',scope:'openid',state:actor.state,nonce:actor.nonce,code_challenge:actor.challenge,code_challenge_method:'S256'});
      await page.goto(origin+'/oidc/authorize?'+query);
      await page.waitForFunction(() => location.search==='' && document.getElementById('prepare'));
      assert.equal(prepares,0);assert.equal(decisions,0);
      const response=page.waitForResponse(r => new URL(r.url()).pathname==='/v1/oidc/consent/prepare');
      await page.locator('#prepare').click();assert.equal((await response).status(),200);
      await page.locator('#preview').waitFor({state:'visible'});
      assert.equal(await page.locator('#client').textContent(),id);
      assert.equal(await page.evaluate(() => document.cookie),'');
      await Promise.all([page.waitForURL(url => url.hostname==='client.example'),page.locator('#approve').click()]);
      assert.equal(prepares,1);assert.equal(decisions,1);
      assert.ok(callback.searchParams.get('state')===actor.state);
      assert.equal(callback.searchParams.get('iss'),origin);
      code=callback.searchParams.get('code');assert.match(code,/^[A-Za-z0-9_-]{43}$/);
    });
    await check('separate-cookie-free-https-client-redeems-and-node-verifies-production-token',async () => {
      const wrong=await actor.token(code,id,true);
      assert.equal(wrong.status,400);assert.deepEqual(wrong.value,{error:'invalid_grant'});
      const healthy=await actor.token(code,id);
      assert.equal(healthy.status,200);assert.equal(healthy.headers['cache-control'],'no-store');
      assert.equal(healthy.headers.pragma,'no-cache');assert.equal(healthy.headers['set-cookie'],undefined);
      tokens=healthy.value;assert.equal(tokens.token_type,'Bearer');assert.equal(tokens.scope,'openid');
      const discovery=await actor.request('/.well-known/openid-configuration');
      assert.equal(discovery.status,200);assert.equal(discovery.value.issuer,origin);
      assert.equal(discovery.value.jwks_uri,origin+'/oidc/jwks');
      const jwks=await actor.request('/oidc/jwks');assert.equal(jwks.status,200);
      actor.verify(tokens.id_token,jwks.value,id);
    });
    await check('code-replay-is-refused-and-issued-access-is-no-local-session',async () => {
      const replay=await actor.token(code,id);
      assert.equal(replay.status,400);assert.deepEqual(replay.value,{error:'invalid_grant'});
      assert.equal((await actor.request('/v1/session',null,tokens.access_token)).status,401);
      await page.goto(origin+'/');
      assert.equal(await page.evaluate(async () => (await fetch('/v1/session')).status),200);
      const privacy=await page.evaluate(() => ({cookie:document.cookie,local:localStorage.length,session:sessionStorage.length}));
      assert.deepEqual(privacy,{cookie:'',local:0,session:0});
    });
    assert.equal(errors,0);return passed;
  } finally {code=null;tokens=null;callback=null;await context.close();}
}
module.exports={run};
