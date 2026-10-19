'use strict';
const assert = require('node:assert/strict');
const {post, start, goodCredential, finish} = require('./browser.cjs');
const AUTH_START = '/v1/passkeys/authentication/start';
const AUTH_FINISH = '/v1/passkeys/authentication/finish';

async function profile(page, expected = 200) {
  const result = await page.evaluate(async () => {
    const response = await fetch('/v1/session');
    return {status: response.status, body: await response.json()};
  });
  assert.equal(result.status, expected, 'protected session status');
  return result.body;
}

async function enroll(page, discoverable = false) {
  const owner = await profile(page);
  const pending = await start(page, {discoverable});
  if (discoverable) {
    assert.equal(pending.options.publicKey.authenticatorSelection.residentKey, 'required');
  }
  const credential = await goodCredential(page, pending);
  await finish(page, pending, credential);
  const logout = await post(page, '/v1/logout', {});
  assert.equal(logout.status, 204);
  await profile(page, 401);
  return {owner: owner.id, credentialId: credential.id};
}

async function startLogin(page, mode, owner) {
  const result = await post(page, AUTH_START, {mode, ...(owner ? {account_id: owner} : {})});
  assert.equal(result.status, 200, 'authentication start');
  assert.deepEqual(Object.keys(result.body).sort(), ['options', 'transaction_id']);
  assert.equal(result.body.options.publicKey.userVerification, 'required');
  assert.equal(result.body.options.publicKey.rpId, 'localhost');
  if (mode !== 'account_bound') assert.equal(result.body.options.publicKey.allowCredentials.length, 0);
  if (mode === 'conditional') assert.equal(result.body.options.mediation, 'conditional');
  else assert.equal(result.body.options.mediation, undefined);
  return result.body;
}

async function get(page, options) {
  return page.evaluate(async options => {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), 5000);
    try {
      const publicKey = PublicKeyCredential.parseRequestOptionsFromJSON(options.publicKey);
      publicKey.timeout = 2000;
      const credential = await navigator.credentials.get({publicKey, signal: controller.signal,
        ...(options.mediation ? {mediation: options.mediation} : {})});
      return {credential: credential.toJSON()};
    } catch (error) { return {error: error.name}; }
    finally { clearTimeout(timer); }
  }, options);
}

async function assertion(page, pending) {
  const result = await get(page, pending.options);
  assert.equal(Boolean(result.credential), true, 'native assertion must succeed');
  return result.credential;
}

async function complete(page, pending, credential, expected = 204) {
  const result = await post(page, AUTH_FINISH, {transaction_id: pending.transaction_id, credential});
  assert.equal(result.status, expected, 'authentication finish');
  return result;
}

module.exports = {AUTH_START, AUTH_FINISH, profile, enroll, startLogin, get, assertion, complete};
