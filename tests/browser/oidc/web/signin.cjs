'use strict';
const assert=require('node:assert/strict');
const {request,finishBody,signedClaims}=require('./browser.cjs');

async function run({view,provider,proxy,owner,mode,record,status,origin,restart}) {
  let originalOwner;
  await record('configured-routes-and-no-bootstrap',async()=>{
    await view.page.goto(origin+'/oidc/sign-in');
    assert.equal((await request(view.page,'/v1/session')).status,401);
    assert.equal((await request(view.page,'/fixture/session',{})).status,404,'no fixture session-delivery endpoint');
    const privateStatus=(await request(view.page,'/private')).status;
    assert.equal(privateStatus,mode==='embedded'?401:404);
    await status({users:0,sessions:0,identities:0,audit:0,pending:0});
    return {configured_factory:true,auth_only_settings_refused:true,no_bootstrap_endpoint:true,no_seeded_authority:true};
  });
  await record('callback-get-cannot-sign-in-and-cancel-is-denial-only',async()=>{
    await view.begin();await view.login();
    await status({users:0,sessions:0,identities:0,audit:0,pending:1});
    assert.equal((await request(view.page,'/v1/session')).status,401);
    const cookies=await view.context.cookies();
    const proof=cookies.filter(c=>c.name.startsWith('__Host-auth-oidc-signin-'));
    assert.equal(proof.length,4);assert.equal(proof.every(c=>c.httpOnly&&c.secure&&c.sameSite==='Lax'&&c.path==='/'),true);
    assert.equal(cookies.some(c=>c.name==='__Host-auth-session'),false);
    await restart();
    await status({users:0,sessions:0,identities:0,audit:0,pending:1});
    await view.cancel();await status({users:0,sessions:0,identities:0,audit:0,pending:0});
    return {callback_nonmutating:true,four_protected_cookies:true,pending_callback_survives_factory_restart:true,explicit_cancellation:true};
  });
  await record('token-infrastructure-is-503-not-an-auth-rejection',async()=>{
    await view.begin();await view.login();proxy.mode('unavailable');
    try{await view.finish('signin',503);}finally{proxy.mode('normal');}
    await status({users:0,sessions:0,identities:0,audit:0,pending:0});
    assert.equal((await request(view.page,'/v1/session')).status,401);
    return {controlled_token_outage:true,http_status:503,no_cookie_or_database_grant:true};
  });
  await record('public-signin-waits-for-real-final-commit',async()=>{
    await view.begin();const callback=await view.login();
    assert.equal((await owner.command('hold_audit')).result,'held');
    let settled=false,responseObserved=false;
    const completing=view.finish('signin',204,()=>{responseObserved=true;}).then(value=>{settled=true;return {value};},error=>{settled=true;return {error};});
    try {
      const waiting=await owner.command('wait_gate');assert.equal(waiting.result,'waiting');assert.equal(waiting.gate,'final_audit');assert.equal(waiting.original_cap_live,true);
      assert.equal(settled,false,'completion cannot precede commit');
      assert.equal(responseObserved,false,'actual HTTP response must wait for the final audit commit');
      assert.equal((await view.context.cookies()).some(cookie=>cookie.name==='__Host-auth-session'),false,'no session cookie delivery before commit');
      await status({users:0,sessions:0,identities:0,audit:0,pending:0});
      assert.equal((await request(view.page,'/v1/session')).status,401);
    } finally {assert.equal((await owner.command('release')).result,'released');}
    const completed=await completing;if(completed.error)throw completed.error;
    const proof=signedClaims(view,provider,proxy,provider.subject);
    await status({users:1,sessions:1,live_sessions:1,identities:1,audit:1,pending:0,provider_users:1,oidc_sessions:1});
    const user=await request(view.page,'/v1/session');assert.equal(user.status,200);assert.equal(user.body.email,null);originalOwner=user.body.id;
    if(mode==='embedded'){const privateUser=await request(view.page,'/private');assert.equal(privateUser.status,200);assert.equal(privateUser.body.id,originalOwner);}
    const cookie=(await view.context.cookies()).find(c=>c.name==='__Host-auth-session');assert.equal(Boolean(cookie),true);
    assert.equal(cookie.httpOnly&&cookie.secure&&cookie.sameSite==='Lax'&&cookie.path==='/',true);
    assert.equal((await view.context.cookies()).some(c=>c.name.startsWith('__Host-auth-oidc-signin-')),false);
    await restart();
    const retained=await request(view.page,'/v1/session');assert.equal(retained.status,200);assert.equal(retained.body.id,originalOwner);
    await status({users:1,sessions:1,live_sessions:1,identities:1,audit:1,pending:0});
    // Keep only transient test evidence for the next local replay assertion.
    view.previousCallback=callback;
    return {...proof,real_audit_wait_observed:true,http_response_and_cookie_wait_for_commit:true,no_grant_before_commit:true,session_cookie_protected:true,session_survives_factory_restart:true,committed_owner_and_session:true};
  });
  await record('ambient-session-cannot-switch-and-logout-revokes',async()=>{
    const before=proxy.facts.posts;
    assert.equal((await request(view.page,'/v1/oidc/sign-in/start',{})).status,401);
    assert.equal((await request(view.page,'/v1/oidc/sign-in/finish',finishBody(view.previousCallback))).status,401);
    view.previousCallback=null;assert.equal(proxy.facts.posts,before);
    assert.equal((await request(view.page,'/v1/session')).body.id,originalOwner);
    const old=(await view.context.cookies()).filter(c=>c.name==='__Host-auth-session');
    assert.equal((await request(view.page,'/v1/logout',{})).status,204);
    assert.equal((await request(view.page,'/v1/session')).status,401);
    await view.context.addCookies(old);assert.equal((await request(view.page,'/v1/session')).status,401,'actual old bearer remains revoked');
    assert.equal((await request(view.page,'/v1/logout',{})).status,204);
    await status({users:1,sessions:1,live_sessions:0,identities:1,audit:2,pending:0});
    return {ambient_account_switch_rejected:true,provider_not_contacted:true,old_session_replay_denied:true,explicit_logout:true};
  });
  await record('returning-public-login-reuses-the-original-owner',async()=>{
    await view.begin();await view.login();await view.finish('signin',204);
    signedClaims(view,provider,proxy,provider.subject);
    const user=await request(view.page,'/v1/session');assert.equal(user.status,200);assert.equal(user.body.id,originalOwner);
    await status({users:1,sessions:2,live_sessions:1,identities:1,audit:3,pending:0,provider_users:1,oidc_sessions:2});
    return {real_new_provider_flow:true,existing_owner_reused:true,no_extra_identity_or_contact:true};
  });
}
module.exports={run};
