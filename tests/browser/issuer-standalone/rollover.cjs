'use strict';
const assert=require('node:assert/strict');

async function nodeToken(origin,fixture,consent) {
  const actor=fixture.createClient();
  const id=fixture.readyValue.client_id;
  const query=new URLSearchParams({client_id:id,response_type:'code',redirect_uri:'https://client.example/callback',scope:'openid',state:actor.state,nonce:actor.nonce,code_challenge:actor.challenge,code_challenge_method:'S256'});
  const callback=await consent(origin+'/oidc/authorize?'+query,'approve');
  assert.equal(callback.searchParams.get('state')===actor.state,true);
  assert.equal(callback.searchParams.get('iss'),origin);
  const response=await actor.token(callback.searchParams.get('code'),id);
  assert.equal(response.status,200);assert.equal(response.headers['set-cookie'],undefined);
  return {actor,token:response.value.id_token};
}
async function sdkToken(fixture,consent) {
  const start=await fixture.command('authorize');
  const callback=await consent(start.authorization_url,'approve');
  const response=await fixture.command('complete',{callback:callback.href});
  assert.equal(response.verified,true);assert.equal(response.posts,1);
}
async function run({origin,fixture,mail,page,post,consent,plan}) {
  assert.equal(plan.propagation_seconds,300,'unchanged persisted key prepublication policy');
  // No pending operation spans this wait. Preserve the production interval and
  // genuinely authenticate again; never rewrite ready_at, auth_time or a clock.
  const deadline=plan.observed+(plan.propagation_seconds+1)*1000;
  await new Promise(resolve=>setTimeout(resolve,Math.max(0,deadline-performance.now())));
  await page.goto(origin+'/');
  assert.equal(await post('/v1/email/start',{email:mail.address}),202);
  let proof=await mail.proof(origin);
  assert.equal(await post('/v1/email/finish',{token:proof}),204);proof=null;
  const before=await nodeToken(origin,fixture,consent);
  const oldKeys=(await before.actor.request('/oidc/jwks')).value;
  const id=fixture.readyValue.client_id;
  before.actor.verify(before.token,oldKeys,id);
  // Same ordinary production bytes, different trusted audience expectation.
  assert.throws(()=>before.actor.verify(before.token,oldKeys,fixture.readyValue.native_client_id),assert.AssertionError);
  await sdkToken(fixture,consent);
  await fixture.activateRotation();
  const after=await nodeToken(origin,fixture,consent);
  const keys=(await after.actor.request('/oidc/jwks')).value;
  after.actor.verify(after.token,keys,id);
  before.actor.verify(before.token,keys,id);
  assert.equal(keys.keys.length,2,'old and newly active public keys overlap');
  const kid=token=>JSON.parse(Buffer.from(token.split('.')[0],'base64url')).kid;
  assert.notEqual(kid(before.token),kid(after.token),'normal issuance follows the explicit new key');
  await sdkToken(fixture,consent);
  await page.goto(origin+'/');
  assert.equal(await post('/v1/logout',{}),204);
  return {ordinary_rollover_verified:true,old_key_overlap_verified:true,independent_audience_denial:true,sdk_before_after_rotation:true};
}
module.exports={run};
