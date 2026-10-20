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
  async function flow({expected,person=provider,held=false,nameAbsent=false,subjectMatches=true}={}) {
    const start=await fixture.command('begin');assert.equal(start.result,'started');
    const returned=await callback(browser,start.authorization,person,redirect);
    proxy.mode('normal');const before=proxy.facts.token_responses;
    const result=await fixture.command(held?'identity_finish_held':'finish',{callback:returned});
    assert.equal(result.result,expected,'exact final outcome; infrastructure failures never count as denial');
    assert.equal(result.post_delta,1);assert.equal(proxy.facts.token_responses-before,1,'real successful provider redemption');
    for(const field of ['verified_before_resolution','verified_configuration_matched','original_cap_retained',
      'provider_email_matches_mailbox','provider_email_verified']) {
      if(person===provider || field!=='provider_email_matches_mailbox')assert.equal(result[field],true,field);
    }
    assert.equal(result.subject_matches_original,subjectMatches);
    assert.equal(result.provider_name_absent,nameAbsent);
    assert.equal(result.selected_display_present,!nameAbsent);
    if(expected==='authenticated') for(const field of ['source_provenance_valid','authentication_time_preserved',
      'provider_required','local_contact_absent','different_mailbox_owner','same_provider_owner','stored_display_preserved','mailbox_session_valid'])assert.equal(result[field],true,field);
    if(expected==='unauthorized')assert.equal(result.mailbox_session_valid,true);
    return result;
  }
  async function configure(jit,previous) {
    const result=await fixture.command('identity_configure',{jit});
    assert.equal(result.result,'identity_configured');
    assert.equal(result.previous_provider_session_rejected,previous);
  }
  async function resolveHeld() {
    const result=await fixture.command('identity_resolve_held');
    assert.equal(result.result,'unauthorized');assert.equal(result.post_delta,0);
    for(const field of ['verified_before_resolution','original_cap_live','mailbox_session_valid'])assert.equal(result[field],true,field);
  }
  await record('keycloak-identity-owned-mailbox-control',async()=>{
    const before=await fixture.command('stats');assert.deepEqual(before.facts,{users:0,sessions:0,audit:0,pending:0},'original verifier cases create no local authority');
    await provider.identityClaims();await configure('deny',null);
    const mailbox=await fixture.command('identity_mailbox',{email:provider.email});
    assert.equal(mailbox.result,'mailbox_prepared');assert.equal(mailbox.mailbox_session_valid,true);
    const facts=await fixture.command('stats');assert.deepEqual(facts.facts,{users:1,sessions:1,audit:1,pending:0});
  });
  await record('keycloak-valid-proof-default-jit-deny',async()=>{
    await flow({expected:'unauthorized'});
    const facts=await fixture.command('stats');assert.deepEqual(facts.facts,{users:1,sessions:1,audit:1,pending:0});
  });
  await record('keycloak-explicit-jit-no-matching-email-merge',async()=>{
    await configure('allow',null);await flow({expected:'authenticated'});
    const facts=await fixture.command('stats');assert.deepEqual(facts.facts,{users:2,sessions:2,audit:2,pending:0});
  });
  await record('keycloak-bound-subject-without-optional-profile',async()=>{
    await provider.optionalProfile();
    assert.equal((await fixture.command('identity_profile',{enabled:false})).result,'profile_configured');
    await flow({expected:'authenticated',nameAbsent:true});
    const facts=await fixture.command('stats');assert.deepEqual(facts.facts,{users:2,sessions:3,audit:3,pending:0});
  });
  await record('keycloak-verified-proof-rejected-after-policy-revision',async()=>{
    assert.equal((await fixture.command('identity_profile',{enabled:true})).result,'profile_configured');
    await flow({expected:'held',held:true});
    await configure('deny',true);await resolveHeld();
  });
  await record('keycloak-jit-deny-still-resolves-bound-subject',async()=>{
    assert.equal((await fixture.command('identity_profile',{enabled:false})).result,'profile_configured');
    await flow({expected:'authenticated',nameAbsent:true});
    const facts=await fixture.command('stats');assert.deepEqual(facts.facts,{users:2,sessions:4,audit:4,pending:0});
  });
  await record('keycloak-jit-denies-new-valid-subject-with-usable-display',async()=>{
    const other=await provider.anotherUser();
    assert.equal((await fixture.command('identity_profile',{enabled:true})).result,'profile_configured');
    await flow({expected:'unauthorized',person:{...provider,...other},subjectMatches:false});
  });
  await record('keycloak-verified-proof-and-session-rejected-after-disable',async()=>{
    await flow({expected:'held',held:true});
    assert.equal((await fixture.command('disable')).result,'disabled');await resolveHeld();
    const status=await fixture.command('identity_status');assert.equal(status.result,'identity_status');
    assert.equal(status.provider_session_rejected,true);assert.equal(status.mailbox_session_valid,true);
    const facts=await fixture.command('stats');assert.deepEqual(facts.facts,{users:2,sessions:4,audit:4,pending:0});
  });
  assert.deepEqual(proxy.facts,{posts:15,token_responses:14,signature_mutations:1,token_replays:1});
  return results;
}
module.exports={run};
