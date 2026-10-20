'use strict';
const assert=require('node:assert/strict');
const {request,finishBody,signedClaims}=require('./browser.cjs');

async function run({view,provider,proxy,owner,record,status}) {
  await record('wrong-fresh-provider-subject-cannot-delete',async()=>{
    const other={...provider,...await provider.anotherUser()};
    await view.begin('delete');await view.login(other,'delete');
    await status({users:1,sessions:2,live_sessions:1,identities:1,audit:3,pending:1});
    await view.finish('delete',401);
    const proof=signedClaims(view,provider,proxy,other.subject);
    await status({users:1,sessions:2,live_sessions:1,identities:1,audit:3,pending:0});
    assert.equal((await request(view.page,'/v1/session')).status,200);
    return {...proof,wrong_subject_denied:true,original_account_session_preserved:true};
  });
  await record('explicit-fresh-deletion-erases-and-rejects-old-proof',async()=>{
    await view.begin('delete');const callback=await view.login(provider,'delete');
    const old=await view.context.cookies();
    const before=proxy.facts.posts;
    await view.page.locator('#confirmation').fill('yes');await view.page.locator('#confirm').click();
    await status({users:1,sessions:2,live_sessions:1,identities:1,audit:3,pending:1});
    assert.equal(proxy.facts.posts,before,'no token exchange without destructive confirmation');
    await view.finish('delete',204);const proof=signedClaims(view,provider,proxy,provider.subject);
    await status({users:0,sessions:0,live_sessions:0,identities:0,audit:4,pending:0,cooldown:1,live_cooldown:1,retained_subjects:0});
    assert.equal((await request(view.page,'/v1/session')).status,401);
    assert.equal((await view.context.cookies()).some(c=>c.name.startsWith('__Host-auth-')),false);
    await view.context.addCookies(old);const count=proxy.facts.posts;
    assert.equal((await request(view.page,'/v1/account/provider-delete/finish',finishBody(callback,'delete'))).status,401);
    assert.equal(proxy.facts.posts,count);assert.equal((await request(view.page,'/v1/logout',{})).status,204);
    return {...proof,explicit_destructive_confirmation:true,all_local_authority_erased:true,retained_audit_deidentified:true,old_cookies_and_callback_replay_denied:true};
  });
  await record('cooldown-rejects-a-verified-public-signin-at-subject-resolution',async()=>{
    await view.begin();await view.login();
    assert.equal((await owner.command('hold_subject',{subject:provider.subject})).result,'held');
    let settled=false,responseObserved=false;
    const completing=view.finish('signin',401,()=>{responseObserved=true;}).then(value=>{settled=true;return {value};},error=>{settled=true;return {error};});
    try {
      const waiting=await owner.command('wait_gate');assert.equal(waiting.result,'waiting');assert.equal(waiting.gate,'verified_subject_resolution');assert.equal(waiting.original_cap_live,true);
      assert.equal(settled,false,'verified completion must reach the actual scoped subject lock');
      assert.equal(responseObserved,false,'authorization response must follow actual verified subject resolution');
      await status({users:0,sessions:0,identities:0,audit:4,pending:0,cooldown:1,live_cooldown:1,retained_subjects:0});
    }finally{assert.equal((await owner.command('release')).result,'released');}
    const completed=await completing;if(completed.error)throw completed.error;
    const proof=signedClaims(view,provider,proxy,provider.subject);
    await status({users:0,sessions:0,identities:0,audit:4,pending:0,cooldown:1,live_cooldown:1,retained_subjects:0});
    assert.equal((await request(view.page,'/v1/session')).status,401);
    return {...proof,verified_sql_resolution_observed:true,original_cap_live:true,live_cooldown_denied_jit:true,no_reprovisioned_authority:true};
  });
}
module.exports={run};
