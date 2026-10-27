'use strict';
const assert=require('node:assert/strict');
const {open}=require('./journey.cjs');
const fixtureHttp=require('./fixture-http.cjs');

async function run(browser,origin) {
  const journey=await open(browser,origin), {page}=journey, results=[];
  async function check(name,action) {
    console.log(JSON.stringify({case:name,status:'running'}));
    try {await action();} catch(error) {error.caseName=name; throw error;}
    results.push({name,status:'passed'}); console.log(JSON.stringify({case:name,status:'passed'}));
  }
  try {
    await check('apple-cross-site-delivery-does-not-consume-or-exchange',async()=>{
      await journey.returned();
      assert.deepEqual(await journey.facts(),{users:0,identities:0,sessions:0,audit:0,pending:1,posts:0,signed:0});
      assert.equal(await journey.profile(),401); assert.equal(journey.counters().finishes,0); await journey.cancel();
    });
    await check('apple-denial-never-mints-session',async()=>{await journey.returned('denied');await journey.finish(401);assert.equal(await journey.profile(),401);});
    await check('apple-provider-failure-is-unavailable',async()=>{await journey.returned('provider_failure');await journey.finish(503);assert.equal(await journey.profile(),401);});
    await check('apple-malformed-form-leaves-pending-for-explicit-cancellation',async()=>{
      await journey.returned('bad_form'); assert.equal((await journey.facts()).pending,1);
      assert.equal(await journey.profile(),401); await journey.clean();
    });
    await check('apple-unsigned-profile-cannot-execute-or-render',async()=>{await journey.returned('profile');await journey.privacy();await journey.cancel();});
    await check('apple-restored-page-discards-return-without-completion',async()=>{
      await journey.returned();const before=journey.counters().finishes;
      await page.evaluate(()=>{dispatchEvent(new PageTransitionEvent('pagehide',{persisted:true}));dispatchEvent(new PageTransitionEvent('pageshow',{persisted:true}));});
      assert.equal(await page.locator('#confirm').isHidden(),true);assert.equal(journey.counters().finishes,before);
      assert.equal(await journey.profile(),401);await journey.clean();
    });
    await check('apple-lost-finish-is-never-retried',async()=>{
      await journey.returned();
      await page.route('**/v1/apple/sign-in/finish',route=>route.abort());
      await page.locator('#continue').click();
      await page.waitForFunction(()=>document.getElementById('status').textContent.includes('not confirmed'));
      assert.equal(await page.locator('#confirm').isHidden(),true);assert.equal((await journey.facts()).posts,0);
      await page.unroute('**/v1/apple/sign-in/finish');await journey.cancel();
    });
    await check('apple-actual-signed-wrong-nonce-is-rejected',async()=>{await journey.returned('wrong_nonce');await journey.finish(401);assert.equal(await journey.profile(),401);assert.equal((await journey.facts()).signed,1);});
    await check('apple-private-browser-proof-and-deliberate-verified-commit',async()=>{
      await journey.returned();const raw=journey.deliveries.at(-1).body;
      assert.equal((await fixtureHttp.request(origin,'/v1/apple/sign-in/finish',{response:raw})).status,401);
      assert.equal((await journey.facts()).posts,1);assert.equal(await journey.profile(),401);
      await journey.finish(204);assert.equal(await journey.profile(),200);
      const replay=await page.evaluate(async response=>(await fetch('/v1/apple/sign-in/finish',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({response})})).status,raw);
      assert.equal(replay,401);
      assert.deepEqual(await journey.facts(),{users:1,identities:1,sessions:1,audit:1,pending:0,posts:2,signed:2});
    });
    await check('apple-current-session-prevents-start',async()=>{
      await page.goto(origin+'/apple/sign-in');const before=journey.counters().providerRequests;
      const response=page.waitForResponse(r=>new URL(r.url()).pathname==='/v1/apple/sign-in/start');
      await page.locator('#continue').click();assert.equal((await response).status(),401);
      assert.equal(journey.counters().providerRequests,before);assert.equal(await journey.profile(),200);
    });
    await check('apple-lax-ambient-session-returns-only-on-protected-finish',async()=>{
      const current=(await journey.context.cookies()).find(c=>c.name==='__Host-auth-session'); assert(current);
      const arrival=await open(browser,origin);
      try {
        arrival.arrival(current);await arrival.returned();assert.equal(await arrival.profile(),200);
        await arrival.finish(401);assert.equal(await arrival.profile(),200);
        assert.equal((await arrival.facts()).posts,2);await arrival.cancel();assert.equal(await arrival.profile(),200);
        assert.equal(arrival.counters().errors,0);
        assert.equal(arrival.counters().fixtureFailures,0);
        assert.equal(arrival.counters().cspViolations,0);
      } finally {await arrival.close();}
    });
    assert.equal(journey.counters().errors,0);
    assert.equal(journey.counters().fixtureFailures,0);
    assert.equal(journey.counters().cspViolations,0);
    assert.equal((await journey.facts()).pending,0);
    return results;
  } finally {await journey.close();}
}
module.exports={run};
