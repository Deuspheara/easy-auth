'use strict';
const assert=require('node:assert/strict');
const {callback}=require('../browser.cjs');
const {client,request,finishBody}=require('./browser.cjs');

async function run(fixture,provider,proxy,browser,origin,redirect) {
  const results=[];
  const view=await client(browser,origin,provider.issuer);
  let calls=0;
  async function record(name,action) {
    console.log(JSON.stringify({case:name,status:'running'}));
    let facts;
    try{facts=await action();}catch(error){error.caseName=name;throw error;}
    results.push({name,status:'passed',...facts});console.log(JSON.stringify({case:name,status:'passed'}));
  }
  async function status(deleted,pending) {
    const value=await fixture.command('status');
    assert.equal(value.result,'status');assert.equal(value.current_session_valid,!deleted);
    assert.equal(value.configured_source_current,true);assert.equal(value.mail_calls,0);
    assert.equal(value.deletion_calls,calls);
    assert.deepEqual(value.http_facts,deleted?
      {users:0,sessions:0,identities:0,audit:2,pending:0,cooldown:1,notices:0,contacts:0,live_cooldown:1,retained_subjects:0}:
      {users:1,sessions:1,identities:1,audit:1,pending,cooldown:0,notices:0,contacts:0,live_cooldown:0,retained_subjects:1});
    return value;
  }
  function verified(value,matches,result) {
    assert.equal(value.last_deletion.subject_matches,matches);
    for(const field of ['configuration_matches','purpose_bound','signed_time_present','signed_time_recent','original_cap_live']) {
      assert.equal(value.last_deletion[field],true,field);
    }
    assert.equal(value.last_deletion.result,result);
  }
  try {
    await record('keycloak-http-real-provider-session-bootstrap',async()=>{
      const start=await fixture.command('begin');assert.equal(start.result,'started');
      const returned=await callback(browser,start.authorization,provider,redirect);
      const issued=await fixture.command('finish',{callback:returned});
      assert.equal(issued.result,'authenticated');assert.equal(issued.local_contact_absent,true);assert.equal(issued.post_delta,1);
      assert.equal((await fixture.command('replay_state')).result,'unauthorized');
      await view.page.goto(origin+'/oidc/account-delete');
      assert.equal(await request(view.page,'/v1/session'),401);
      assert.equal(await request(view.page,'/fixture/session',{capability:issued.bootstrap_capability}),204);
      assert.equal(await request(view.page,'/fixture/session',{capability:issued.bootstrap_capability}),401,'fixture capability is one-use');
      assert.equal(await request(view.page,'/v1/session'),200);
      const cookies=await view.context.cookies(origin);
      const session=cookies.find(cookie=>cookie.name==='__Host-auth-session');
      assert.equal(session.httpOnly,true);assert.equal(session.secure,true);assert.equal(session.sameSite,'Lax');
      await status(false,0);
      for(const value of Object.values(issued.verified_proof))assert.equal(value,true);
      return {actual_signed_bootstrap:true,one_use_cookie_delivery:true,session_cookie_protected:true,local_contact_absent:true};
    });
    await record('keycloak-http-callback-get-and-cancellation-cannot-delete',async()=>{
      await view.begin();await view.login(provider);
      await status(false,1); // GET performed no verification, consumption or deletion.
      const cookies=await view.context.cookies(origin);
      const proofs=cookies.filter(cookie=>cookie.name.startsWith('__Host-auth-oidc-delete-'));
      assert.equal(proofs.length,4);
      assert.equal(proofs.every(cookie=>cookie.httpOnly&&cookie.secure&&cookie.sameSite==='Lax'&&cookie.path==='/'),true);
      const response=view.page.waitForResponse(r=>r.url()===origin+'/v1/account/provider-delete/cancel');
      await view.page.locator('#cancel').click();assert.equal((await response).status(),204);
      await view.page.waitForFunction(()=>document.getElementById('status').textContent.startsWith('Pending deletion cancelled.'));
      await status(false,0);
      assert.equal((await view.context.cookies(origin)).some(cookie=>cookie.name.startsWith('__Host-auth-oidc-delete-')),false);
      return {callback_get_preserves_pending_and_account:true,explicit_cancellation:true,four_protected_proof_cookies:true};
    });
    await record('keycloak-http-wrong-fresh-signed-subject-denied',async()=>{
      const other={...provider,...await provider.anotherUser()};
      await view.begin();await view.login(other);await status(false,1);
      await view.finish(401);calls++;
      const value=await status(false,0);verified(value,false,'unauthorized');
      return {verified_deletion:value.last_deletion,original_account_session_retained:true};
    });
    await record('keycloak-http-token-infrastructure-failure-is-503',async()=>{
      await view.begin();await view.login(provider);await status(false,1);
      proxy.mode('unavailable');
      try{await view.finish(503);}finally{proxy.mode('normal');}
      await status(false,0);assert.equal(proxy.faults.unavailable,1);
      return {controlled_token_unavailability:true,http_status:503,no_verified_deletion_or_account_mutation:true};
    });
    await record('keycloak-http-explicit-reauthentication-deletion-and-replay',async()=>{
      await view.begin();const returned=await view.login(provider);await status(false,1);
      const originalCookies=await view.context.cookies(origin);
      await view.page.locator('#confirmation').fill('yes');await view.page.locator('#confirm').click();
      await status(false,1); // Browser validation cannot become confirmation.
      await view.finish(204);calls++;
      const committed=await status(true,0);verified(committed,true,'committed');
      assert.equal(await request(view.page,'/v1/session'),401);
      const remaining=await view.context.cookies(origin);
      assert.equal(remaining.some(cookie=>cookie.name.startsWith('__Host-auth-')),false);
      const before=proxy.facts.posts;
      // Restore only the actually issued pre-deletion cookies inside this owned
      // browser. Its real DNS/TLS path must perform the rejection, not Node's
      // separate API-request resolver (which has no fixture hostname mapping).
      await view.context.addCookies(originalCookies);
      assert.equal(await request(view.page,'/v1/account/provider-delete/finish',finishBody(returned)),401);
      assert.equal(proxy.facts.posts,before);
      await status(true,0);
      return {verified_deletion:committed.last_deletion,explicit_confirmation:true,no_surviving_session:true,old_cookie_and_callback_replay_denied:true};
    });
    await record('keycloak-http-deletion-cooldown-rejects-fresh-bootstrap-proof',async()=>{
      const start=await fixture.command('begin');assert.equal(start.result,'started');
      const returned=await callback(browser,start.authorization,provider,redirect);
      const rejected=await fixture.command('finish',{callback:returned});
      assert.equal(rejected.result,'unauthorized');assert.equal(rejected.post_delta,1);
      for(const value of Object.values(rejected.verified_proof))assert.equal(value,true);
      assert.equal((await fixture.command('replay_state')).result,'unauthorized');
      await status(true,0);
      return {fresh_signed_proof:rejected.verified_proof,live_cooldown:true,local_authority_remains_absent:true};
    });
    assert.deepEqual(proxy.facts,{posts:5,token_responses:4,signature_mutations:0,token_replays:0});
    return results;
  } finally {await view.close();}
}
module.exports={run};
