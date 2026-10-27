'use strict';
const assert=require('node:assert/strict');
const fixtureHttp=require('../apple-web/fixture-http.cjs');
const {open}=require('../social/journey.cjs');

async function run(browser,origin,erase) {
  const j=await open(browser,origin),results=[];
  let owner,original,provider;
  const snapshot=async()=>{const r=await fixtureHttp.request(origin,'/fixture/grants');assert.equal(r.status,200);return JSON.parse(r.text);};
  const attempt=async failure=>{const r=await fixtureHttp.request(origin,'/fixture/grants/run',{failure});assert.equal(r.status,200);return JSON.parse(r.text).outcome;};
  const state=(active,pending,completed,encrypted,attempts,calls)=>({active,pending,leased:0,failed:0,completed,expired:0,encrypted,attempts,calls});
  const session=async context=>(await context.cookies()).find(c=>c.name==='__Host-auth-session');
  const inventory=async(target=j)=>{const r=await target.json('/v1/account/providers');assert.equal(r.status,200);return r.body.providers;};
  async function check(name,action) {
    console.log(JSON.stringify({case:name,status:'running'}));
    try {await action();} catch(error) {error.caseName=name;throw error;}
    results.push({name,status:'passed'});console.log(JSON.stringify({case:name,status:'passed'}));
  }
  try {
    await check('genuine-email-owner-and-no-implicit-provider-grant',async()=>{
      owner=await j.email(j.page,'owner@owned.example');original=await session(j.context);assert(original);
      assert.deepEqual(await snapshot(),state(0,0,0,0,0,0));
      assert.equal(await attempt(false),'idle');
    });
    await check('cancelled-cross-site-apple-return-captures-no-grant',async()=>{
      await j.returned('apple');await j.cancel('apple');
      assert.deepEqual(await snapshot(),state(0,0,0,0,0,0));
      assert.equal((await session(j.context)).value,original.value);
    });
    await check('actually-signed-wrong-nonce-cannot-capture-or-link',async()=>{
      await j.returned('apple','wrong_nonce');await j.finish('apple',401);
      assert.equal((await inventory()).length,0);
      assert.deepEqual(await snapshot(),state(0,0,0,0,0,0));
    });
    await check('explicit-owner-confirmation-links-and-protects-one-grant',async()=>{
      await j.returned('apple');assert.deepEqual(await snapshot(),state(0,0,0,0,0,0));
      await j.finish('apple');assert.equal((await inventory()).length,1);
      assert.deepEqual(await snapshot(),state(1,0,0,1,0,0));
      assert.equal((await session(j.context)).value,original.value);
    });
    await check('linked-apple-signin-captures-another-grant-without-changing-owner',async()=>{
      provider=await open(browser,origin);const page=provider.page;
      await page.goto(origin+'/apple/sign-in');
      await Promise.all([page.waitForURL(url=>url.pathname==='/apple/callback'),page.locator('#continue').click()]);
      await page.locator('#confirm').waitFor({state:'visible'});await provider.privacy('apple');
      const completed=page.waitForResponse(r=>new URL(r.url()).pathname==='/v1/apple/sign-in/finish');
      await page.locator('#continue').click();assert.equal((await completed).status(),204);
      assert.equal((await provider.json('/v1/session')).body.id,owner.id);
      assert.deepEqual(await snapshot(),state(2,0,0,2,0,0));
      await provider.accounts();
      const denied=page.waitForResponse(r=>new URL(r.url()).pathname==='/v1/account/providers/oidc/unlink');
      await page.locator('#providers button').click();assert.equal((await denied).status(),401);
      assert.equal((await provider.json('/v1/session')).status,200);
      assert.deepEqual(await snapshot(),state(2,0,0,2,0,0));
    });
    await check('local-retained-factor-unlink-queues-both-grants-before-provider-io',async()=>{
      await j.accounts();const response=j.page.waitForResponse(r=>new URL(r.url()).pathname==='/v1/account/providers/oidc/unlink');
      await j.page.locator('#providers button').click();assert.equal((await response).status(),204);
      assert.deepEqual(await snapshot(),state(0,2,0,2,0,0));
      assert.equal((await inventory()).length,0);
      assert.equal((await provider.json('/v1/session')).status,401);
      assert.equal((await session(j.context)).value,original.value);
      assert.equal((await j.json('/v1/session')).body.id,owner.id);
    });
    await check('provider-configuration-failure-retains-ciphertext-and-cannot-busy-retry',async()=>{
      assert.equal(await attempt(true),'deferred_configuration');
      assert.deepEqual(await snapshot(),state(0,2,0,2,1,1));
      // The other original job can complete; the failed one stays behind the
      // actual database backoff, with no test clock or direct SQL mutation.
      assert.equal(await attempt(false),'confirmed');
      assert.deepEqual(await snapshot(),state(0,1,1,1,2,2));
      assert.equal(await attempt(false),'idle');
      assert.deepEqual(await snapshot(),state(0,1,1,1,2,2));
      assert.equal((await j.json('/v1/session')).body.id,owner.id);
    });
    await check('actual-backoff-retry-confirms-erasure-with-retained-session-intact',async()=>{
      const deadline=Date.now()+45000;let outcome;
      do {
        await new Promise(resolve=>setTimeout(resolve,250));
        outcome=await attempt(false);assert(['idle','confirmed'].includes(outcome));
      } while(outcome==='idle'&&Date.now()<deadline);
      assert.equal(outcome,'confirmed');
      assert.deepEqual(await snapshot(),state(0,0,2,0,3,3));
      assert.equal(await attempt(false),'idle');
      assert.equal((await session(j.context)).value,original.value);
      assert.equal((await j.json('/v1/session')).body.id,owner.id);
      assert.equal((await provider.json('/v1/session')).status,401);
    });
    await check('feature-disabled-erasure-preserves-protected-grant-and-worker-can-finish',async()=>{
      const other=await open(browser,origin);
      try {
        const erased=await other.email(other.page,'erase@owned.example');
        assert.notEqual(erased.id,owner.id);
        await other.returned('apple','other_subject');await other.finish('apple');
        assert.deepEqual(await snapshot(),state(1,0,2,1,3,3));
        const cookie=await session(other.context);assert(cookie);
        assert.deepEqual(erase(cookie.value,erased.realm_id),{deletion_confirmed:true,captured_rows_preserved:1,
          ciphertext_unchanged:true,capture_selected:false,linking_selected:false});
        assert.equal((await other.json('/v1/session')).status,401);
        assert.deepEqual(await snapshot(),state(0,1,2,1,3,3));
        assert.equal(await attempt(false),'confirmed');
        assert.deepEqual(await snapshot(),state(0,0,3,0,4,4));
        assert.equal((await j.json('/v1/session')).body.id,owner.id);
        assert.equal((await session(j.context)).value,original.value);
      } finally {await other.close();}
    });
    assert.deepEqual(j.counters(),{errors:0,violations:0,failures:0,finishes:2});
    assert.deepEqual(provider.counters(),{errors:0,violations:0,failures:0,finishes:0});
    return results;
  } finally {if(provider)await provider.close();await j.close();}
}
module.exports={run};
