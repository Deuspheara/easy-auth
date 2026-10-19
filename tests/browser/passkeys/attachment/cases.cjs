'use strict';
const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const {post, withAuthenticator} = require('../browser.cjs');
const {profile, assertion, startLogin, complete} = require('../assertions.cjs');
const {signupAssertion, successfulSignup} = require('../signup/ceremony.cjs');
const START = '/v1/account/email/attachment/start';
const FINISH = '/v1/account/email/attachment/finish';

async function denyWeakPaths(page, address) {
  for (const [path, body] of [
    ['/v1/password/enroll', {password: 'a sufficiently long example password'}],
    ['/v1/account/email/start', {email: address}],
    ['/v1/account/delete/start', {confirmation: 'delete my account'}]
  ]) assert.equal((await post(page, path, body)).status, 401, 'stronger policy remains enforced');
}

async function confirm(page, context, peer, mail, origin, address) {
  assert.equal((await post(page, START, {email: address.toUpperCase()})).status, 202);
  const binding = (await context.cookies()).find(cookie => cookie.name === 'auth-attach');
  assert.equal(Boolean(binding?.httpOnly && binding.sameSite === 'Lax'), true, 'independent HttpOnly binding');
  const proof = await mail.proof(address, origin);
  const denied = body => peer.request.post(origin + FINISH, {headers: {Origin: origin}, data: body});
  assert.equal((await denied({token: proof.token})).status(), 401, 'session alone lacks mailbox binding');
  await peer.addCookies([{name: 'auth-attach', value: crypto.randomBytes(32).toString('base64url'),
    url: origin, httpOnly: true, sameSite: 'Lax'}]);
  assert.equal((await denied({token: proof.token})).status(), 401, 'wrong independent browser binding');
  const get = await context.request.get(proof.link);
  assert.equal(get.status(), 200);
  assert.equal(get.headers()['cache-control'].includes('no-store'), true);
  assert.equal(get.headers()['content-security-policy'].includes("script-src 'self'"), true);
  assert.equal((await profile(page)).email, null, 'GET consumes no proof');
  await page.goto(proof.link);
  assert.equal(new URL(page.url()).hash, '', 'reference script removes proof fragment');
  assert.equal((await profile(page)).email, null, 'page load consumes nothing');
  await page.locator('#confirm').click();
  await page.waitForFunction(() => document.getElementById('status').textContent ===
    'Contact email confirmed. Your passkey is still required to sign in.');
  assert.equal((await context.cookies()).some(cookie => cookie.name === 'auth-attach'), false);
  return proof;
}

async function runCases(browser, origin, mail) {
  const results = [];
  const firstAddress = mail.recipient(0);
  for (const [index, transport] of ['internal', 'usb'].entries()) {
    const name = `native-signup-smtp-contact-${transport}`;
    console.log(JSON.stringify({case: name, status: 'running'}));
    try {
      await withAuthenticator(browser, origin, undefined, transport, async ({page, context}) => {
        assert.equal((await context.cookies()).some(cookie => cookie.name === 'auth-session'), false);
        const {pending, assertionOptions} = await signupAssertion(page);
        const owner = await successfulSignup(page, pending, assertionOptions, await assertion(page, assertionOptions));
        const old = (await context.cookies()).find(cookie => cookie.name === 'auth-session');
        const peer = await browser.newContext();
        try {
          await peer.addCookies([old]);
          const address = index ? mail.recipient(index) : firstAddress;
          if (index) {
            // The first independently proved account already owns this target.
            assert.equal((await post(page, START, {email: firstAddress})).status, 202, 'occupied target generic');
            const occupied = await mail.proof(firstAddress, origin);
            assert.equal((await post(page, FINISH, {token: occupied.token})).status, 401, 'no matching-email merge');
            assert.equal((await profile(page)).id, owner.id);
            assert.equal((await profile(page)).email, null);
          }
          const proof = await confirm(page, context, peer, mail, origin, address);
          const attached = await profile(page);
          assert.equal(attached.id, owner.id, 'same opaque owner');
          assert.equal(attached.email === address, true, 'verified normalized contact');
          assert.equal(attached.display_name, owner.display_name);
          const current = (await context.cookies()).find(cookie => cookie.name === 'auth-session');
          assert.equal(current.value !== old.value, true, 'session rotates');
          await peer.addCookies([old]);
          assert.equal((await peer.request.get(origin + '/v1/session')).status(), 401, 'old session revoked');
          assert.equal((await post(page, FINISH, {token: proof.token})).status, 401, 'proof cannot replay');
          await denyWeakPaths(page, address);
          assert.equal((await post(page, '/v1/logout', {})).status, 204);
          for (const mode of ['account_bound', 'discoverable']) {
            const login = await startLogin(page, mode, mode === 'account_bound' ? owner.id : undefined);
            await complete(page, login, await assertion(page, login));
            const later = await profile(page);
            assert.equal(later.id, owner.id);
            assert.equal(later.email === address, true);
            assert.equal((await post(page, '/v1/logout', {})).status, 204);
          }
        } finally { await peer.close(); }
      });
    } catch (error) { error.caseName = name; throw error; }
    results.push({name, transport, status: 'passed', native_signup: true, smtp_contact: true,
      later_account_bound_and_discoverable: true, ...(index ? {occupied_target_rejected: true} : {})});
    console.log(JSON.stringify({case: name, status: 'passed'}));
  }
  return results;
}
module.exports = {runCases};
