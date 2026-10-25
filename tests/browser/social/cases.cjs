'use strict';
const assert=require('node:assert/strict');
const {open}=require('./journey.cjs');
async function run(browser,origin,probe) {
  const j=await open(browser,origin), {page}=j, results=[];
  let owner,original,providerJourney;
  const session=async()=> (await j.context.cookies()).find(c=>c.name==='__Host-auth-session');
  const providers=async()=>{const r=await j.json('/v1/account/providers');assert.equal(r.status,200);return r.body.providers;};
  async function check(name,action) {
    console.log(JSON.stringify({case:name,status:'running'}));
    try {await action();}catch(e){e.caseName=name;throw e;}
    results.push({name,status:'passed'});console.log(JSON.stringify({case:name,status:'passed'}));
  }
  try {
    await check('genuine-email-owner-and-explicit-management',async()=>{
      owner=await j.email(page,'owner@owned.example');original=await session();assert(original);
      await j.accounts();assert((await page.locator('#owner').textContent()).includes(owner.email));
      assert.equal((await providers()).length,0);
    });
    await check('google-return-waits-for-explicit-owner-confirmation',async()=>{
      await j.returned('google');assert.equal((await providers()).length,0);assert.equal(j.counters().finishes,0);
      assert.equal((await session()).value,original.value);await j.cancel('google');
    });
    await check('apple-cross-site-return-has-no-cookies-or-mutation',async()=>{
      await j.returned('apple');assert.equal((await providers()).length,0);
      assert((await page.locator('#status').textContent()).includes(owner.email));await j.cancel('apple');
    });
    await check('restored-google-return-cannot-finish-or-retry',async()=>{
      await j.returned('google');const before=j.counters().finishes;
      await page.evaluate(()=>{dispatchEvent(new PageTransitionEvent('pagehide',{persisted:true}));dispatchEvent(new PageTransitionEvent('pageshow',{persisted:true}));});
      assert.equal(await page.locator('#confirm').isHidden(),true);assert.equal(j.counters().finishes,before);
      await j.accounts();const r=page.waitForResponse(r=>new URL(r.url()).pathname==='/v1/account/google-link/cancel');
      await page.locator('[data-cancel=google]').click();assert.equal((await r).status(),204);
    });
    await check('late-apple-presentation-hint-cannot-reenable-restored-return',async()=>{
      let entered,release,done;
      const arrived=new Promise(resolve=>{entered=resolve;}),gate=new Promise(resolve=>{release=resolve;}),finished=new Promise(resolve=>{done=resolve;});
      await page.route('**/v1/apple/return-operation',async route=>{entered();await gate;await route.continue().catch(()=>{});done();});
      try {
        j.mode('normal');await j.accounts();
        await Promise.all([page.waitForURL(url=>url.pathname==='/apple/callback'),page.locator('[data-link=apple]').click()]);
        await arrived;const before=j.counters().finishes;
        await page.evaluate(()=>{dispatchEvent(new PageTransitionEvent('pagehide',{persisted:true}));dispatchEvent(new PageTransitionEvent('pageshow',{persisted:true}));});
        release();await finished;
        assert.equal(await page.locator('#confirm').isHidden(),true);assert.equal(j.counters().finishes,before);
      } finally {release();await page.unroute('**/v1/apple/return-operation');}
      await j.accounts();const response=page.waitForResponse(r=>new URL(r.url()).pathname==='/v1/account/apple-link/cancel');
      await page.locator('[data-cancel=apple]').click();assert.equal((await response).status(),204);
    });
    await check('signed-wrong-nonce-cannot-link',async()=>{
      await j.returned('apple','wrong_nonce');await j.finish('apple',401);assert.equal((await providers()).length,0);
      assert.equal((await session()).value,original.value);
    });
    await check('lost-link-finish-drops-return-and-never-retries',async()=>{
      await j.returned('google');const before=j.counters().finishes;await page.route('**/v1/account/google-link/finish',r=>r.abort());
      await page.locator('#confirm button').click();await page.waitForFunction(()=>document.getElementById('status').textContent.includes('not confirmed'));
      assert.equal(await page.locator('#confirm').isHidden(),true);assert.equal((await providers()).length,0);
      assert.equal(j.counters().finishes,before+1);
      await page.locator('#confirm').evaluate(form=>form.dispatchEvent(new Event('submit',{cancelable:true})));
      assert.equal(j.counters().finishes,before+1);
      await page.unroute('**/v1/account/google-link/finish');await j.cancel('google');
    });
    await check('old-return-cannot-cancel-new-link',async()=>{
      await j.returned('google');const old=page;
      const newer=await j.context.newPage();await j.accounts(newer);
      let response=newer.waitForResponse(r=>new URL(r.url()).pathname==='/v1/account/google-link/cancel');
      await newer.locator('[data-cancel=google]').click();assert.equal((await response).status(),204);
      await j.returned('google','normal',newer);
      response=old.waitForResponse(r=>new URL(r.url()).pathname==='/v1/account/google-link/cancel');
      await old.locator('#cancel').click();assert.equal((await response).status(),401);
      await j.finish('google',204,newer);await newer.close();
      assert.equal((await providers()).length,1);assert.equal((await session()).value,original.value);
    });
    await check('apple-confirmation-links-to-same-owner-without-replacing-session',async()=>{
      await j.returned('apple');await j.finish('apple');assert.equal((await providers()).length,2);
      assert.equal((await j.json('/v1/session')).body.id,owner.id);assert.equal((await session()).value,original.value);
    });
    await check('linked-provider-login-keeps-owner-and-cannot-unlink-current-source',async()=>{
      providerJourney=await open(browser,origin);const target=providerJourney.page;
      await target.goto(origin+'/google/sign-in');
      await Promise.all([target.waitForURL(url=>url.pathname==='/google/callback'),target.locator('#continue').click()]);
      await target.locator('#confirm-form').waitFor({state:'visible'});
      const completed=target.waitForResponse(r=>new URL(r.url()).pathname==='/v1/google/sign-in/finish');
      await target.locator('#continue').click();assert.equal((await completed).status(),204);
      assert.equal((await providerJourney.json('/v1/session')).body.id,owner.id);
      await providerJourney.accounts();
      const denied=target.waitForResponse(r=>new URL(r.url()).pathname==='/v1/account/providers/oidc/unlink');
      await target.locator('#providers li').filter({hasText:'https://accounts.google.com'}).locator('button').click();
      assert.equal((await denied).status(),401);assert.equal((await providerJourney.json('/v1/session')).status,200);
      await j.accounts();
      if(process.env.EASY_AUTH_SOCIAL_WEB_SCREENSHOT)await page.screenshot({path:process.env.EASY_AUTH_SOCIAL_WEB_SCREENSHOT,fullPage:true});
    });
    await check('build-without-linking-rejects-real-linked-source-but-keeps-local-session',async()=>{
      const user=(await providerJourney.json('/v1/session')).body;
      const cookie=(await providerJourney.context.cookies()).find(c=>c.name==='__Host-auth-session');assert(cookie);
      assert.equal(probe(original.value,owner.realm_id),true,'ordinary local control remains valid');
      assert.equal(probe(cookie.value,user.realm_id),false,'feature-disabled binary cannot accept linked mailbox OIDC');
      assert.equal((await providerJourney.json('/v1/session')).status,200,'same source remains valid in selected linking build');
    });
    await check('account-switch-invalidates-captured-management-view',async()=>{
      await j.accounts();const other=await open(browser,origin);
      try {
        const user=await other.email(other.page,'other@owned.example');assert.notEqual(user.id,owner.id);
        const cookie=(await other.context.cookies()).find(c=>c.name==='__Host-auth-session');
        await j.context.addCookies([cookie]);const before=j.counters().finishes;
        await page.locator('[data-link=google]').click();
        await page.waitForFunction(()=>document.getElementById('actions').hidden);
        assert.equal(j.counters().finishes,before);assert.equal((await providers()).length,0);
      } finally {await other.close();await j.context.addCookies([original]);}
      await j.accounts();assert.equal((await providers()).length,2);
    });
    await check('deliberate-owned-unlink-retains-current-session',async()=>{
      for(let index=0;index<2;index++) {
        await j.accounts();const response=page.waitForResponse(r=>new URL(r.url()).pathname==='/v1/account/providers/oidc/unlink');
        await page.locator('#providers button').first().click();assert.equal((await response).status(),204);
        await page.waitForFunction(expected=>document.querySelectorAll('#providers li').length===expected,1-index);
        assert.equal((await session()).value,original.value);
      }
      assert.equal((await providers()).length,0);assert.equal((await j.json('/v1/session')).body.id,owner.id);
      assert.equal((await providerJourney.json('/v1/session')).status,401,'removed source invalidates its genuine provider session');
    });
    assert.deepEqual(j.counters(),{errors:0,violations:0,failures:0,finishes:4});
    return results;
  } finally {if(providerJourney)await providerJourney.close();await j.close();}
}
module.exports={run};
