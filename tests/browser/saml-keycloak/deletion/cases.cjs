'use strict';
const assert=require('node:assert/strict');
const {login,status}=require('../browser.cjs');
const phrase='delete my account';
async function reauthenticate(session,origin,credentials) {
  const page=session.page;
  // Clear only the owned provider's SSO cookies to allow ordinary account selection.
  // The initiating application's session and private proof cookies are untouched.
  await session.context.clearCookies({domain:'fixture.invalid'});
  await page.goto(origin+'/saml/account-delete');
  await page.locator('#delete-start input').fill(phrase);
  await page.getByRole('button',{name:'Continue to reauthentication',exact:true}).click();
  await page.locator('#username').fill(credentials.username);
  await page.locator('#password').fill(credentials.password);
  await page.locator('#kc-login').click();
  await page.locator('#delete-confirm').waitFor();
}
async function confirm(session,expected) {
  const page=session.page;
  await page.locator('#delete-confirm input').fill(phrase);
  const finished=page.waitForResponse(r=>new URL(r.url()).pathname==='/v1/saml/account-delete/finish');
  await page.getByRole('button',{name:'Delete my account',exact:true}).click();
  assert.equal((await finished).status(),expected,'actual deletion completion');
  if(expected===204)await page.waitForURL(url=>url.pathname==='/');
}
async function run(owner,provider,browser,origin,initial) {
  const cases=[];
  await owner.command('configure',{realm:0,certificates:[initial.pin],jit:'allow'});
  const session=await login(browser,origin,provider);
  const facts=async()=>(await owner.command('facts')).facts;
  try {
    const initialFacts=await facts();
    assert.equal(initialFacts.users,1);assert.equal(initialFacts.sessions,1);
    assert.equal(initialFacts.timing.exact_signed_authn,true);
    cases.push('genuine_keycloak_sign_in_precedes_deletion');
    await reauthenticate(session,origin,provider);
    const before=await facts();
    assert.equal(await status(session),200);assert.equal(before.users,1);
    assert.equal(before.sessions,1);assert.equal(before.pending,1);assert.equal(before.replays,2);
    cases.push('actual_signed_return_has_no_authority_before_second_confirmation');
    await session.page.locator('#delete-confirm input').fill('wrong confirmation');
    await session.page.getByRole('button',{name:'Delete my account',exact:true}).click();
    await session.page.getByText('Type the exact confirmation phrase.',{exact:true}).waitFor();
    assert.deepEqual(await facts(),before);
    cases.push('reference_client_requires_exact_second_confirmation');
    await session.page.getByRole('button',{name:'Cancel deletion',exact:true}).click();
    await session.page.getByText('Pending deletion cancelled.',{exact:true}).waitFor();
    assert.equal((await facts()).pending,0);assert.equal(await status(session),200);
    cases.push('returned_operation_cancellation_preserves_owner_and_session');
    const other=await provider.anotherUser();
    await reauthenticate(session,origin,other);
    await confirm(session,401);
    assert.equal(await status(session),200);
    const rejected=await facts();
    assert.equal(rejected.users,1);assert.equal(rejected.identities,1);
    assert.equal(rejected.sessions,1);assert.equal(rejected.pending,0);assert.equal(rejected.replays,2);
    cases.push('real_other_provider_subject_cannot_erase_initiating_owner');
    await reauthenticate(session,origin,provider);
    await confirm(session,204);
    assert.equal(await status(session),401);
    const erased=await facts();
    for(const name of ['users','identities','sessions','pending'])assert.equal(erased[name],0,name);
    assert.equal(erased.replays,4);
    assert.equal(erased.timing.grants,1);assert.equal(erased.timing.removed_sessions,1);
    assert.equal(erased.timing.exact_signed_authn,null,'erased session timing unavailable');
    cases.push('fresh_actual_keycloak_assertion_commits_local_erasure_and_retains_replay');
    const users=await provider.admin('/users?username='+encodeURIComponent(provider.username)+'&exact=true');
    assert.equal(users.length,1);assert.equal(users[0].id,provider.subject);
    cases.push('local_deletion_preserves_remote_identity_provider_account');
    return {cases,facts:{before_erasure:initialFacts,after_erasure:erased}};
  } finally {await session.context.close();}
}
module.exports={run};
