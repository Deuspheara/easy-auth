'use strict';
const assert = require('node:assert/strict');
const {post, create, goodCredential, withAuthenticator} = require('../browser.cjs');
const {profile, startLogin, assertion, complete} = require('../assertions.cjs');
const {frameAssertion} = require('../frame-assertion.cjs');
const {SIGNUP_START, SIGNUP_REGISTRATION, SIGNUP_FINISH, startSignup, registerSignup,
  finishSignup, signupAssertion, successfulSignup} = require('./ceremony.cjs');

async function runSignupCases(browser, origin, existingSession) {
  const results = [];
  async function run(name, transport, operation) {
    console.log(JSON.stringify({case: name, status: 'running'}));
    let detail;
    try { detail = await withAuthenticator(browser, origin, undefined, transport, operation); }
    catch (error) { error.caseName = name; throw error; }
    results.push({name, transport, status: 'passed', signup: true, signup_finishes: 2, ...(detail || {})});
    console.log(JSON.stringify({case: name, status: 'passed'}));
  }
  for (const transport of ['internal', 'usb']) {
    await run(`signup-anonymous-resident-${transport}`, transport, async ({page, context}) => {
      assert.equal((await context.cookies()).some(cookie => cookie.name === 'auth-session'), false);
      const {pending, creation, assertionOptions} = await signupAssertion(page);
      await registerSignup(page, pending, creation, 401);
      const credential = await assertion(page, assertionOptions);
      const user = await successfulSignup(page, pending, assertionOptions, credential);
      assert.equal((await context.cookies()).find(cookie => cookie.name === 'auth-session').httpOnly, true);
      for (const [path, body] of [
        ['/v1/password/enroll', {password: 'a sufficiently long example password'}],
        ['/v1/account/email/start', {email: 'verified-contact@example.test'}],
        ['/v1/account/delete/start', {confirmation: 'delete my account'}]
      ]) assert.equal((await post(page, path, body)).status, 401, 'no weaker account operation');
      assert.equal((await post(page, '/v1/logout', {})).status, 204);
      await finishSignup(page, assertionOptions, credential, 401);
      for (const mode of ['account_bound', 'discoverable']) {
        const login = await startLogin(page, mode, mode === 'account_bound' ? user.id : undefined);
        const proof = await assertion(page, login);
        if (mode === 'discoverable') assert.equal(Boolean(proof.response.userHandle), true);
        await complete(page, login, proof);
        assert.equal((await profile(page)).id, user.id);
        assert.equal((await profile(page)).email, null);
        assert.equal((await post(page, '/v1/logout', {})).status, 204);
      }
      return {signup_finishes: 4, authentications: 2};
    });
  }
  for (const field of ['challenge', 'origin']) {
    await run(`signup-registration-rejects-${field}`, 'internal', async ({page}) => {
      const pending = await startSignup(page);
      const good = await goodCredential(page, pending);
      const bad = structuredClone(good);
      const data = JSON.parse(Buffer.from(bad.response.clientDataJSON, 'base64url').toString());
      data[field] = field === 'origin' ? 'http://localhost:1' : 'wrong-signup-challenge';
      bad.response.clientDataJSON = Buffer.from(JSON.stringify(data)).toString('base64url');
      await registerSignup(page, pending, bad, 401);
      const options = await registerSignup(page, pending, good);
      await successfulSignup(page, pending, options, await assertion(page, options));
      return {signup_finishes: 3};
    });
  }
  await run('signup-browser-rejects-unrelated-rp', 'internal', async ({page}) => {
    const pending = await startSignup(page);
    const bad = structuredClone(pending.options);
    bad.publicKey.rp.id = 'example.com';
    assert.equal((await create(page, bad)).error, 'SecurityError');
    const options = await registerSignup(page, pending, await goodCredential(page, pending));
    await successfulSignup(page, pending, options, await assertion(page, options));
  });
  await run('signup-registration-requires-uv', 'internal', async ({page, cdp, authenticatorId}) => {
    const pending = await startSignup(page);
    await cdp.send('WebAuthn.setResponseOverrideBits', {authenticatorId, isBadUV: true});
    const bad = await create(page, pending.options);
    if (bad.credential) await registerSignup(page, pending, bad.credential, 401);
    else assert.equal(bad.error, 'NotAllowedError');
    await cdp.send('WebAuthn.setResponseOverrideBits', {authenticatorId});
    const options = await registerSignup(page, pending, await goodCredential(page, pending));
    await successfulSignup(page, pending, options, await assertion(page, options));
    return {signup_finishes: bad.credential ? 3 : 2, rejected_by: bad.credential ? 'server' : 'browser'};
  });
  for (const [name, override] of [['uv', 'isBadUV'], ['up', 'isBadUP'], ['signature', 'isBogusSignature']]) {
    await run(`signup-assertion-rejects-${name}`, 'usb', async ({page, cdp, authenticatorId}) => {
      const {pending, assertionOptions} = await signupAssertion(page);
      await cdp.send('WebAuthn.setResponseOverrideBits', {authenticatorId, [override]: true});
      await finishSignup(page, assertionOptions, await assertion(page, assertionOptions), 401);
      await profile(page, 401);
      await cdp.send('WebAuthn.setResponseOverrideBits', {authenticatorId});
      await successfulSignup(page, pending, assertionOptions, await assertion(page, assertionOptions));
      return {signup_finishes: 3};
    });
  }
  await run('signup-rejects-session-and-other-browser-confusion', 'internal', async ({page, context}) => {
    const pending = await startSignup(page);
    const creation = await goodCredential(page, pending);
    await context.addCookies([{name: 'auth-session', value: existingSession, url: origin,
      httpOnly: true, sameSite: 'Lax', secure: false}]);
    const existing = await profile(page);
    assert.equal(typeof existing.email, 'string');
    for (const [path, body] of [[SIGNUP_START, {display_name: 'Another account'}],
      [SIGNUP_REGISTRATION, {transaction_id: pending.transaction_id, credential: creation}]]) {
      assert.equal((await post(page, path, body)).status, 401);
      assert.equal((await profile(page)).id, existing.id);
    }
    assert.equal((await post(page, '/v1/logout', {})).status, 204);
    const peer = await browser.newContext();
    try {
      const denied = await peer.request.post(origin + SIGNUP_REGISTRATION, {headers: {Origin: origin},
        data: {transaction_id: pending.transaction_id, credential: creation}});
      assert.equal(denied.status(), 401);
      const options = await registerSignup(page, pending, creation);
      const proof = await assertion(page, options);
      const deniedFinish = await peer.request.post(origin + SIGNUP_FINISH, {headers: {Origin: origin},
        data: {transaction_id: pending.transaction_id, credential: proof}});
      assert.equal(deniedFinish.status(), 401);
      await successfulSignup(page, pending, options, proof);
    } finally { await peer.close(); }
  });
  await run('signup-rejects-signed-cross-origin-assertion', 'usb', async ({page}) => {
    const {pending, assertionOptions} = await signupAssertion(page);
    await frameAssertion(page, origin, assertionOptions, finishSignup);
    await profile(page, 401);
    await successfulSignup(page, pending, assertionOptions, await assertion(page, assertionOptions));
    return {signup_finishes: 3};
  });
  return results;
}

module.exports = {runSignupCases};
