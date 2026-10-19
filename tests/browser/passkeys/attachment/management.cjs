'use strict';
const assert = require('node:assert/strict');
const {post, start, goodCredential, finish} = require('../browser.cjs');
const {profile, assertion, startLogin, complete} = require('../assertions.cjs');

async function inventory(page) {
  const response = await page.evaluate(async () => {
    const response = await fetch('/v1/passkeys');
    return {status: response.status, body: await response.json(), cache: response.headers.get('cache-control')};
  });
  assert.equal(response.status, 200, 'fresh genuine passkey inventory');
  assert.equal(response.cache.includes('no-store'), true);
  const keys = response.body.passkeys;
  for (const key of keys) assert.deepEqual(Object.keys(key).sort(),
    ['created_at_ms', 'id', 'label', 'last_used_at_ms', 'version']);
  return keys;
}

function selectCredential(pending, id, expectedPresent) {
  // Narrow client selection for a positive proof, or deliberately request the
  // removed authenticator for a real signed negative. Server state is untouched.
  const options = structuredClone(pending);
  if (expectedPresent) assert.equal(options.options.publicKey.allowCredentials.some(key => key.id === id), true);
  options.options.publicKey.allowCredentials = [{type: 'public-key', id}];
  return options;
}

async function manage({page, context, peer, cdp, authenticatorId, transport, origin, owner, initialCredential, mail, address}) {
  let stage = 'initial_inventory';
  try {
    const first = (await inventory(page))[0];
    assert.equal(Number.isInteger(first.last_used_at_ms), true, 'signup asserted the first credential');
    const renamed = await post(page, '/v1/passkeys/rename', {id: first.id, version: first.version, label: 'Native managed key'});
    assert.equal(renamed.status, 200);
    assert.equal(renamed.body.version !== first.version, true);
    assert.equal((await post(page, '/v1/passkeys/rename', {id: first.id, version: first.version, label: 'Stale version'})).status, 401);
    const removal = {id: first.id, version: renamed.body.version};
    assert.equal((await post(page, '/v1/passkeys/remove', removal)).status, 401, 'last proven key protected');
    stage = 'first_notice';
    await mail.notices(address, 1);
    stage = 'spare_registration';
    // Use an independent native authenticator; excludeCredentials correctly prevents
    // registering the already-bound device again. Presence chooses the device only.
    await cdp.send('WebAuthn.setAutomaticPresenceSimulation', {authenticatorId, enabled: false});
    const {authenticatorId: spareAuthenticator} = await cdp.send('WebAuthn.addVirtualAuthenticator', {options: {
      protocol: 'ctap2', transport: transport === 'internal' ? 'usb' : 'internal',
      hasResidentKey: true, hasUserVerification: true, isUserVerified: true, automaticPresenceSimulation: true
    }});
    const pending = await start(page, {discoverable: true});
    assert.equal(pending.options.publicKey.authenticatorSelection.residentKey, 'required');
    const credential = await goodCredential(page, pending);
    const registered = await finish(page, pending, credential);
    const spare = (await inventory(page)).find(key => key.id === registered.body.id);
    assert.equal(Boolean(spare), true);
    assert.equal(spare.last_used_at_ms, null, 'registration alone grants no proven-use marker');
    assert.equal((await post(page, '/v1/passkeys/remove', removal)).status, 401, 'unproven spare cannot replace working key');
    stage = 'spare_sign_in';
    const login = await startLogin(page, 'account_bound', owner.id);
    await complete(page, login, await assertion(page, selectCredential(login, credential.id, true)));
    assert.equal(Number.isInteger((await inventory(page)).find(key => key.id === spare.id).last_used_at_ms), true);
    const current = (await context.cookies()).find(cookie => cookie.name === 'auth-session');
    await peer.addCookies([current]);
    stage = 'removal_and_cookie_clear';
    assert.equal((await post(page, '/v1/passkeys/remove', removal)).status, 204);
    assert.equal((await context.cookies()).some(cookie => cookie.name.startsWith('auth-')), false, 'all auth/action cookies cleared');
    assert.equal((await peer.request.get(origin + '/v1/session')).status(), 401, 'other current session revoked');
    await profile(page, 401);
    stage = 'second_notice';
    await mail.notices(address, 2);
    stage = 'removed_key_and_retry';
    const retry = await startLogin(page, 'account_bound', owner.id);
    assert.equal(retry.options.publicKey.allowCredentials.some(key => key.id === initialCredential.id), false, 'removed key absent');
    await cdp.send('WebAuthn.setAutomaticPresenceSimulation', {authenticatorId: spareAuthenticator, enabled: false});
    await cdp.send('WebAuthn.setAutomaticPresenceSimulation', {authenticatorId, enabled: true});
    const removedProof = await assertion(page, selectCredential(retry, initialCredential.id, false));
    await complete(page, retry, removedProof, 401);
    await profile(page, 401);
    await cdp.send('WebAuthn.setAutomaticPresenceSimulation', {authenticatorId, enabled: false});
    await cdp.send('WebAuthn.setAutomaticPresenceSimulation', {authenticatorId: spareAuthenticator, enabled: true});
    // The same genuine challenge remains usable by the surviving credential.
    await complete(page, retry, await assertion(page, selectCredential(retry, credential.id, true)));
    const after = await profile(page);
    assert.equal(after.id, owner.id);
    assert.equal(after.email === address, true);
    const remaining = await inventory(page);
    assert.equal(remaining.length, 1);
    assert.equal(remaining[0].id, spare.id);
  } catch (error) { error.stageName = stage; throw error; }
}

module.exports = {manage};
