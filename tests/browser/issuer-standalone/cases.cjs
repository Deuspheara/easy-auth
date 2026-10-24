'use strict';
const assert=require('node:assert/strict');
async function run(browser,origin,fixture,actor,mail) {
  const context=await browser.newContext({ignoreHTTPSErrors:true});
  const page=await context.newPage();
  let actualCallback,errors=0,stage="signin";
  page.on('pageerror',()=>{errors++;});
  await context.route('**/*',async route=>{
    const url=new URL(route.request().url());
    if(url.origin===origin)return route.continue();
    if(url.origin==='https://client.example'&&url.pathname==='/callback') {
      actualCallback=url;
      return route.fulfill({status:200,contentType:'text/html',headers:{'Cache-Control':'no-store'},body:'<!doctype html><title>Owned RP return</title>'});
    }
    return route.abort();
  });
  async function post(path,body) {
    return page.evaluate(async ({path,body})=>(await fetch(path,{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(body)})).status,{path,body});
  }
  async function consent(url,decision) {
    actualCallback=null;await page.goto(url);
    await page.waitForFunction(()=>location.search===''&&document.getElementById('prepare'));
    const prepared=page.waitForResponse(r=>new URL(r.url()).pathname==='/v1/oidc/consent/prepare');
    await page.locator('#prepare').click();assert.equal((await prepared).status(),200);
    await page.locator('#preview').waitFor({state:'visible'});
    await Promise.all([page.waitForURL(url=>url.hostname==='client.example'),page.locator('#'+decision).click()]);
    assert.equal(Boolean(actualCallback),true);return actualCallback;
  }
  try {
    await page.goto(origin+'/');
    assert.equal(await post('/v1/email/start',{email:mail.address}),202);
    let token=await mail.proof(origin);
    assert.equal(await post('/v1/email/finish',{token}),204);token=null;
    stage="node-client";
    const id=fixture.readyValue.client_id;
    // Separate standard HTTPS/Node client uses its own S256/state/nonce and no cookies.
    const query=new URLSearchParams({client_id:id,response_type:'code',redirect_uri:'https://client.example/callback',scope:'openid',state:actor.state,nonce:actor.nonce,code_challenge:actor.challenge,code_challenge_method:'S256'});
    const callback=await consent(origin+'/oidc/authorize?'+query,'approve');
    assert.equal(callback.searchParams.get('state')===actor.state,true);
    assert.equal(callback.searchParams.get('iss'),origin);
    const code=callback.searchParams.get('code');
    const response=await actor.token(code,id);
    assert.equal(response.status,200);
    assert.equal(response.headers['cache-control'],'no-store');
    assert.equal(response.headers['set-cookie'],undefined);
    const discovery=await actor.request('/.well-known/openid-configuration');
    assert.equal(discovery.status,200);assert.equal(discovery.value.issuer,origin);
    const jwks=await actor.request('/oidc/jwks');assert.equal(jwks.status,200);
    actor.verify(response.value.id_token,jwks.value,id);
    assert.equal((await actor.token(code,id)).status,400);
    assert.equal((await actor.request('/v1/session',null,response.value.access_token)).status,401);
    // The Rust client performs real discovery, callback validation, POST and JOSE verification.
    stage='rust-client';
    const start=await fixture.command('authorize');
    const sdkCallback=await consent(start.authorization_url,'approve');
    const complete=await fixture.command('complete',{callback:sdkCallback.href});
    assert.equal(complete.verified,true);assert.equal(complete.posts,1);assert.equal(complete.subject_pairwise,true);
    stage='rust-denial';
    const denied=await fixture.command('authorize');
    const denialCallback=await consent(denied.authorization_url,'cancel');
    const result=await fixture.command('complete',{callback:denialCallback.href});
    assert.equal(result.denied,true);assert.equal(result.posts,0);
    stage='privacy-logout';
    await page.goto(origin+'/');
    assert.equal(await page.evaluate(async ()=>(await fetch('/v1/session')).status),200);
    assert.deepEqual(await page.evaluate(()=>({cookie:document.cookie,local:localStorage.length,session:sessionStorage.length})),{cookie:'',local:0,session:0});
    assert.equal(await post('/v1/logout',{}),204);
    assert.equal(await page.evaluate(async ()=>(await fetch('/v1/session')).status),401);
    assert.equal(errors,0);
    return {smtp_signin:true,node_production_token:true,code_replay_rejected:true,access_is_not_local_session:true,
      sdk_verified:true,bound_denial_without_post:true,browser_privacy:true,logout:true};
  } catch(error) {error.caseName=stage;throw error;} finally {actualCallback=null;await context.close();}
}
module.exports={run};
