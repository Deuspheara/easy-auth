'use strict';
const assert = require('node:assert/strict');
const {callback}=require('./browser.cjs');

async function run(fixture,provider,proxy,browser,redirect) {
  const results=[];
  async function record(name,action) {
    console.log(JSON.stringify({case:name,status:'running'}));
    try {await action();} catch(error) {error.caseName=name;throw error;}
    results.push({name,status:'passed'});
    console.log(JSON.stringify({case:name,status:'passed'}));
  }
  async function flow({expected='verified',mutation,proxyMode='normal'}={}) {
    // No runner pacing: application admission must handle genuine no-store metadata.
    const started=await fixture.command('begin');
    assert.equal(started.result,'started','real PostgreSQL begin and metadata control');
    const returned=await callback(browser,started.authorization,provider,redirect,mutation);
    proxy.mode(proxyMode);
    const responsesBefore=proxy.facts.token_responses;
    const result=await fixture.command('finish',{callback:returned});
    assert.equal(result.result,expected,'exact application outcome, never arbitrary failure');
    assert.equal(result.post_delta,1);
    assert.equal(proxy.facts.token_responses-responsesBefore,mutation==='pkce'?0:1,
      'claim/signature negatives must reach a successful provider token response');
    if (mutation==='nonce') assert.equal(proxy.lastClaims().nonce!==new URL(started.authorization).searchParams.get('nonce'),true);
    if (expected==='verified') {
      for (const field of ['subject_matches','same_configuration','original_cap_retained','email_absent']) assert.equal(result[field],true,field);
      assert.equal(result.email_verified,false);
    }
    return result;
  }
  await record('keycloak-real-code-s256-and-rs256',()=>flow());
  await record('postgres-consumed-state-replay',async()=>{
    const replay=await fixture.command('replay_state');
    assert.equal(replay.result,'unauthorized');assert.equal(replay.post_delta,0);
  });
  await record('keycloak-exact-code-and-verifier-replay',async()=>{assert.equal(await proxy.replayCode(),true);});
  await record('keycloak-signed-wrong-nonce',()=>flow({expected:'unauthorized',mutation:'nonce'}));
  await record('keycloak-rejects-wrong-s256-proof',()=>flow({expected:'unauthorized',mutation:'pkce'}));
  await record('controlled-corruption-of-keycloak-signature',()=>flow({expected:'unauthorized',proxyMode:'bad-signature'}));
  await record('captured-keycloak-token-replay-on-fresh-state',()=>flow({expected:'unauthorized',proxyMode:'replay-token'}));
  await record('keycloak-signed-untrusted-additional-audience',async()=>{
    await provider.audience(true);
    try {
      await flow({expected:'unauthorized'});
      const audience=proxy.lastClaims().aud;
      assert.equal(Array.isArray(audience)&&audience.includes(provider.client)&&audience.includes('untrusted-fixture-audience'),true,
        'actual provider-signed audience mismatch is required');
    } finally {await provider.audience(false);}
  });
  await record('keycloak-real-signing-key-rotation',async()=>{
    const rotated=await provider.rotate();
    await flow();
    assert.equal(proxy.lastKid()===rotated,true,'actual new provider signing key must verify');
  });
  await record('fresh-keycloak-success-after-all-negatives',()=>flow());
  await record('disabled-postgres-context-sends-no-code',async()=>{
    const started=await fixture.command('begin');assert.equal(started.result,'started');
    const returned=await callback(browser,started.authorization,provider,redirect);
    const disabled=await fixture.command('disable');assert.equal(disabled.result,'disabled');
    const result=await fixture.command('finish',{callback:returned});
    assert.equal(result.result,'unauthorized');assert.equal(result.post_delta,0);
  });
  assert.deepEqual(proxy.facts,{posts:8,token_responses:7,signature_mutations:1,token_replays:1});
  return results;
}
module.exports={run};
