'use strict';
const assert=require('node:assert/strict');
const {callback}=require('./browser.cjs');

async function run(fixture,provider,proxy,browser,redirect) {
  const results=[];
  async function record(name,action) {
    console.log(JSON.stringify({case:name,status:'running'}));
    try {await action();} catch(error) {error.caseName=name;throw error;}
    results.push({name,status:'passed'});console.log(JSON.stringify({case:name,status:'passed'}));
  }
  async function flow(person,deleting,expected,matches) {
    const start=await fixture.command(deleting?'identity_deletion_begin':'begin');
    assert.equal(start.result,'started');
    const authorization=new URL(start.authorization);
    assert.equal(authorization.searchParams.get('max_age'),deleting?'0':null);
    assert.equal(authorization.searchParams.get('prompt'),deleting?'login':null);
    const returned=await callback(browser,start.authorization,person,redirect);
    proxy.mode('normal');const before=proxy.facts.token_responses;
    const result=await fixture.command('finish',{callback:returned});
    assert.equal(result.result,expected,'only the exact application outcome counts; infrastructure failures are fatal');
    assert.equal(result.post_delta,1);assert.equal(proxy.facts.token_responses-before,1);
    for(const field of ['verified_before_resolution','verified_configuration_matched','original_cap_retained','original_cap_live','mailbox_session_valid'])assert.equal(result[field],true,field);
    assert.equal(result.subject_matches_original,matches);
    if(deleting) {
      for(const field of ['signed_authentication_time_present','signed_authentication_recent','deletion_purpose_bound','initiating_session_valid']) {
        try {assert.equal(result[field],true,field);} catch(error) {error.stageName=field;throw error;}
      }
      assert.equal(result.provider_name_absent,true);assert.equal(result.selected_display_present,false);
      assert.equal(result.provider_session_rejected,expected==='deleted');
    }
    return result;
  }
  async function status(deleted) {
    const value=await fixture.command('identity_deletion_status');
    assert.equal(value.result,'deletion_status');
    for(const field of ['mailbox_session_valid','configured_source_current','persisted_jit_allow'])assert.equal(value[field],true,field);
    assert.equal(value.provider_session_rejected,deleted);
    assert.deepEqual(value.facts,deleted?{deleted:1,live_cooldown:1,erased_provider_audits:4,live_mailbox_audits:1}:{deleted:0,live_cooldown:0,erased_provider_audits:0,live_mailbox_audits:1});
  }
  await record('keycloak-deletion-current-source-control',async()=>{
    assert.deepEqual((await fixture.command('stats')).facts,{users:2,sessions:4,audit:4,pending:0},'all original identity cases retain their exact aggregates');
    await provider.reauthenticationClaims();
    const configured=await fixture.command('identity_configure',{jit:'allow'});
    assert.equal(configured.result,'identity_configured');assert.equal(configured.previous_provider_session_rejected,true);
    assert.equal((await fixture.command('identity_reenable')).result,'identity_reenabled');
    const old=await fixture.command('identity_status');assert.equal(old.provider_session_rejected,true,'latest enable cannot restore old-revision authority');
    assert.equal((await fixture.command('identity_profile',{enabled:false})).result,'profile_configured');
    const result=await flow(provider,false,'authenticated',true);
    for(const field of ['source_provenance_valid','authentication_time_preserved','provider_required','local_contact_absent','different_mailbox_owner','same_provider_owner'])assert.equal(result[field],true,field);
    await status(false);
    assert.deepEqual((await fixture.command('stats')).facts,{users:2,sessions:5,audit:5,pending:0});
  });
  await record('keycloak-deletion-wrong-signed-subject-denied',async()=>{
    const other={...provider,...await provider.anotherUser()};
    await flow(other,true,'unauthorized',false);await status(false);
    assert.deepEqual((await fixture.command('stats')).facts,{users:2,sessions:5,audit:5,pending:0});
  });
  await record('keycloak-reauthentication-and-atomic-provider-deletion',async()=>{
    await flow(provider,true,'deleted',true);await status(true);
    const replay=await fixture.command('replay_state');assert.equal(replay.result,'unauthorized');assert.equal(replay.post_delta,0);
    assert.deepEqual((await fixture.command('stats')).facts,{users:1,sessions:1,audit:6,pending:0});
  });
  await record('keycloak-fresh-valid-subject-cannot-jit-through-deletion-cooldown',async()=>{
    assert.equal((await fixture.command('identity_profile',{enabled:true})).result,'profile_configured');
    const result=await flow(provider,false,'unauthorized',true);
    assert.equal(result.selected_display_present,true,'a missing display must not masquerade as cooldown rejection');
    assert.equal(result.provider_email_matches_mailbox,true);assert.equal(result.provider_email_verified,true);
    await status(true);
    assert.deepEqual((await fixture.command('stats')).facts,{users:1,sessions:1,audit:6,pending:0});
  });
  assert.deepEqual(proxy.facts,{posts:19,token_responses:18,signature_mutations:1,token_replays:1});
  return results;
}
module.exports={run};
