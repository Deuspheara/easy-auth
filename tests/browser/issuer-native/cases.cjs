'use strict';
const assert=require('node:assert/strict');
const {client}=require('../issuer-web/client.cjs');
async function run(browser,origin,certificate,listener) {
  const context=await browser.newContext({ignoreHTTPSErrors:true});
  const page=await context.newPage();
  let actor=client(origin,certificate,listener.redirect),id,code,initial,current,passed=0,errors=0,prepares=0,decisions=0;
  page.on('pageerror',()=>{errors++;});
  context.on('request',request=>{const path=new URL(request.url()).pathname;if(path==='/v1/oidc/native/consent/prepare')prepares++;if(path.endsWith('/approve'))decisions++;});
  await context.route('**/*',route=>{
    const url=new URL(route.request().url());
    if(url.origin===origin || url.origin===listener.origin)return route.continue();
    return route.abort();
  });
  async function check(name,action) {try{await action();}catch(error){error.caseName=name;throw error;}passed++;}
  function authorization() {return origin+'/oidc/authorize?'+new URLSearchParams({client_id:id,response_type:'code',redirect_uri:listener.redirect,scope:'openid offline_access',state:actor.state,nonce:actor.nonce,code_challenge:actor.challenge,code_challenge_method:'S256',prompt:'consent'});}
  async function prepare() {
    const response=page.waitForResponse(r=>new URL(r.url()).pathname==='/v1/oidc/native/consent/prepare');
    await page.locator('#prepare').click();const received=await response;assert.equal(received.status(),200);
    const preview=await received.json();await page.locator('#preview').waitFor({state:'visible'});return preview;
  }
  async function decide(button) {
    const captured=listener.next();
    await Promise.all([page.waitForURL(url=>url.origin===listener.origin && url.pathname==='/done'),page.locator(button).click()]);
    return captured;
  }
  try {
    await check('owned-system-browser-email-and-native-discovery-select-fixed-private-ui',async()=>{
      await page.goto(origin+'/');
      const ok=await page.evaluate(async()=>{
        const post=(path,body)=>fetch(path,{method:'POST',credentials:'same-origin',headers:{'Content-Type':'application/json'},body:JSON.stringify(body)});
        if((await post('/v1/email/start',{email:'owner@example.test'})).status!==202)return false;
        const {token}=await(await fetch('/fixture/mail')).json();return(await post('/v1/email/finish',{token})).status===204;
      });assert.equal(ok,true);
      id=(await actor.request('/fixture/issuer/public')).value.client_id;
      const discovery=await actor.request('/.well-known/openid-configuration');
      assert.deepEqual(discovery.value.grant_types_supported,['authorization_code','refresh_token']);
      assert.deepEqual(discovery.value.scopes_supported,['openid','offline_access']);
      await page.goto(authorization());
      await page.waitForFunction(()=>location.pathname==='/oidc/native/authorize' && location.search==='');
      assert.equal(prepares,0);assert.equal(decisions,0);
    });
    await check('explicit-native-preview-shows-original-offline-bounds-and-reload-recovers-them',async()=>{
      const preview=await prepare();assert.equal(decisions,0);
      assert.equal(await page.locator('#grant-expiry').textContent(),new Date(preview.grant_expires_at_us/1000).toISOString());
      assert.equal(await page.locator('#idle').textContent(),'600');
      assert.equal(await page.locator('#client').textContent(),id);
      assert.equal(await page.locator('#destination').textContent(),listener.redirect);
      await page.reload();const response=page.waitForResponse(r=>new URL(r.url()).pathname.endsWith('/native/consent/resume'));
      await page.locator('#resume').click();const received=await response;assert.equal(received.status(),200);assert.deepEqual(await received.json(),preview);
      await page.locator('#preview').waitFor({state:'visible'});assert.equal(decisions,0);
    });
    await check('explicit-denial-returns-through-real-bound-loopback-without-a-code',async()=>{
      const returned=await decide('#cancel');assert.equal(returned.searchParams.get('state'),actor.state);
      assert.equal(returned.searchParams.get('iss'),origin);assert.equal(returned.searchParams.get('error'),'access_denied');assert.equal(returned.searchParams.has('code'),false);
    });
    await check('explicit-native-approval-returns-code-to-real-loopback-and-separate-client-proves-pkce',async()=>{
      actor=client(origin,certificate,listener.redirect);await page.goto(authorization());
      await page.waitForFunction(()=>location.search==='');await prepare();
      const returned=await decide('#approve');assert.equal(returned.searchParams.get('state'),actor.state);assert.equal(returned.searchParams.get('iss'),origin);
      code=returned.searchParams.get('code');assert.match(code,/^[A-Za-z0-9_-]{43}$/);
      const wrong=await actor.token(code,id,true);assert.equal(wrong.status,400);assert.deepEqual(wrong.value,{error:'invalid_grant'});
      const accepted=await actor.token(code,id);assert.equal(accepted.status,200);
      assert.equal(accepted.headers['set-cookie'],undefined);assert.equal(accepted.headers['cache-control'],'no-store');
      initial=accepted.value;current=initial.refresh_token;assert.equal(initial.scope,'openid offline_access');
      actor.verify(initial.id_token,(await actor.request('/oidc/jwks')).value,id);
      assert.equal((await actor.token(code,id)).status,400);
    });
    await check('one-use-refresh-credentials-rotate-in-client-memory-without-new-id-token-or-cookie',async()=>{
      for(let i=0;i<2;i++) {
        const next=await actor.request('/oidc/token',{grant_type:'refresh_token',client_id:id,refresh_token:current});
        assert.equal(next.status,200);assert.equal(next.headers['set-cookie'],undefined);
        assert.equal(next.value.id_token,undefined);assert.ok(next.value.expires_in>0 && next.value.expires_in<=300);
        assert.notEqual(next.value.refresh_token,current);current=next.value.refresh_token;
      }
      assert.equal((await actor.request('/v1/session',null,initial.access_token)).status,401);
      const introspection=await actor.request('/oidc/introspect',{client_id:id,token:initial.access_token});
      assert.equal(introspection.status,401);
    });
    await check('spent-refresh-replay-permanently-revokes-descendants-and-idempotent-cleanup',async()=>{
      const replay=await actor.request('/oidc/token',{grant_type:'refresh_token',client_id:id,refresh_token:initial.refresh_token});
      assert.equal(replay.status,400);assert.deepEqual(replay.value,{error:'invalid_grant'});
      assert.equal((await actor.request('/oidc/token',{grant_type:'refresh_token',client_id:id,refresh_token:current})).status,400);
      for(const token of [current,'unknown-opaque-value']) {
        const response=await actor.request('/oidc/revoke',{client_id:id,token});assert.equal(response.status,200);assert.equal(response.value,null);
      }
      await page.goto(origin+'/');assert.equal(await page.evaluate(async()=>(await fetch('/v1/session')).status),200);
      assert.deepEqual(await page.evaluate(()=>({cookie:document.cookie,local:localStorage.length,session:sessionStorage.length})),{cookie:'',local:0,session:0});
    });
    assert.equal(errors,0);return passed;
  } finally {code=null;initial=null;current=null;actor=null;await context.close();}
}
module.exports={run};
