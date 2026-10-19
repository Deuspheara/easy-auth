'use strict';
const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const {post, withAuthenticator} = require('../browser.cjs');
const {profile, assertion} = require('../assertions.cjs');
const {signupAssertion, successfulSignup} = require('../signup/ceremony.cjs');
const {confirmContact} = require('./contact.cjs');
const PREPARE = '/v1/passkeys/recovery/code/prepare';
const CONFIRM = '/v1/passkeys/recovery/code/confirm';

async function prepareCode(page) {
  const response = await page.evaluate(async path => {
    const response = await fetch(path, {method: 'POST', headers: {'Content-Type': 'application/json'}, body: '{}'});
    return {status: response.status, cache: response.headers.get('cache-control'), body: await response.json()};
  }, PREPARE);
  assert.equal(response.status, 200);
  assert.equal(response.cache.includes('no-store'), true);
  assert.deepEqual(Object.keys(response.body).sort(), ['code', 'id']);
  const code = response.body.code;
  assert.equal(typeof code === 'string' && /^[A-Za-z0-9_-]{43}$/.test(code) &&
    Buffer.from(code, 'base64url').toString('base64url') === code, true, 'canonical saved code');
  return response.body;
}

async function runRecoveryCases(browser, origin, mail) {
  const results = [];
  for (const [index, transport] of ['internal', 'usb'].entries()) {
    const name = `native-saved-code-configuration-${transport}`;
    console.log(JSON.stringify({case: name, status: 'running'}));
    let stage = 'signup_private_key_proof';
    try {
      await withAuthenticator(browser, origin, undefined, transport, async ({page, context}) => {
        const {pending, assertionOptions} = await signupAssertion(page);
        const owner = await successfulSignup(page, pending, assertionOptions, await assertion(page, assertionOptions));
        assert.equal(owner.email, null);
        const cookies = await context.cookies();
        stage = 'email_free_configuration';
        const first = await prepareCode(page);
        const wrong = {id: first.id, code: crypto.randomBytes(32).toString('base64url')};
        assert.equal((await post(page, CONFIRM, wrong)).status, 401, 'wrong saved code cannot confirm');
        assert.equal((await post(page, CONFIRM, first)).status, 204);
        assert.equal((await post(page, CONFIRM, first)).status, 401, 'confirmation consumes its pending setup');
        assert.equal(JSON.stringify(await context.cookies()) === JSON.stringify(cookies), true, 'configuration issues no session or action cookie');
        const current = await profile(page);
        assert.equal(current.id, owner.id);
        assert.equal(current.email, null);
        stage = 'independent_contact_proof';
        const address = mail.recipient(index + 2);
        const peer = await browser.newContext();
        try {
          const old = cookies.find(cookie => cookie.name === 'auth-session');
          await peer.addCookies([old]);
          await confirmContact(page, context, peer, mail, origin, address);
          assert.equal((await peer.request.get(origin + '/v1/session')).status(), 401, 'contact confirmation revoked the initiating session');
          stage = 'verified_contact_rotation';
          const replacement = await prepareCode(page);
          assert.equal(replacement.id !== first.id && replacement.code !== first.code, true, 'fresh pending code/version');
          assert.equal((await post(page, CONFIRM, replacement)).status, 204);
          assert.equal((await post(page, CONFIRM, replacement)).status, 401);
          await mail.recoveryNotice(address);
          const after = await profile(page);
          assert.equal(after.id, owner.id);
          assert.equal(after.email === address, true);
          assert.equal(await page.evaluate(() => localStorage.length === 0 && sessionStorage.length === 0), true, 'test application persists no saved code in browser storage');
        } finally { await peer.close(); }
      });
    } catch (error) { error.caseName = name; error.stageName = stage; throw error; }
    results.push({name, transport, status: 'passed', native_signup_proof: true,
      email_free_confirmation: true, verified_contact_rotation: true, real_recovery_notice: true});
    console.log(JSON.stringify({case: name, status: 'passed'}));
  }
  return results;
}

module.exports = {runRecoveryCases};
