'use strict';
const assert = require('node:assert/strict');
const {post, goodCredential} = require('../browser.cjs');
const {profile} = require('../assertions.cjs');

const SIGNUP_START = '/v1/passkeys/signup/start';
const SIGNUP_REGISTRATION = '/v1/passkeys/signup/registration';
const SIGNUP_FINISH = '/v1/passkeys/signup/finish';

async function startSignup(page) {
  await profile(page, 401);
  const response = await post(page, SIGNUP_START, {display_name: 'Anonymous browser person'});
  assert.equal(response.status, 200, 'anonymous signup start');
  const {options} = response.body;
  assert.equal(options.publicKey.rp.id, 'localhost');
  assert.equal(options.publicKey.authenticatorSelection.residentKey, 'required');
  assert.equal(options.publicKey.authenticatorSelection.requireResidentKey, true);
  assert.equal(options.publicKey.authenticatorSelection.userVerification, 'required');
  assert.equal(options.publicKey.user.name, 'Anonymous browser person');
  assert.equal(Buffer.from(options.publicKey.user.id, 'base64url').length, 16);
  await profile(page, 401);
  return response.body;
}

async function registerSignup(page, pending, credential, expected = 200) {
  const response = await post(page, SIGNUP_REGISTRATION, {transaction_id: pending.transaction_id, credential});
  assert.equal(response.status, expected, 'signup registration status');
  await profile(page, 401);
  if (expected === 200) {
    assert.equal(response.body.transaction_id, pending.transaction_id);
    assert.equal(response.body.options.publicKey.userVerification, 'required');
    assert.equal(response.body.options.publicKey.allowCredentials.length, 1);
  }
  return response.body;
}

async function finishSignup(page, pending, credential, expected = 204) {
  const response = await post(page, SIGNUP_FINISH, {transaction_id: pending.transaction_id, credential});
  assert.equal(response.status, expected, 'signup assertion status');
  return response;
}

async function signupAssertion(page) {
  const pending = await startSignup(page);
  const creation = await goodCredential(page, pending);
  const assertionOptions = await registerSignup(page, pending, creation);
  return {pending, creation, assertionOptions};
}

async function successfulSignup(page, creationOptions, assertionOptions, credential) {
  await finishSignup(page, assertionOptions, credential);
  const user = await profile(page);
  assert.equal(user.email, null, 'no fabricated email identity');
  assert.equal(user.display_name, 'Anonymous browser person');
  const bytes = Buffer.from(creationOptions.options.publicKey.user.id, 'base64url');
  const uuid = bytes.toString('hex').replace(/^(.{8})(.{4})(.{4})(.{4})(.{12})$/, '$1-$2-$3-$4-$5');
  assert.equal(user.id, uuid, 'actual session owns the server-selected prospective account');
  return user;
}

module.exports = {SIGNUP_START, SIGNUP_REGISTRATION, SIGNUP_FINISH, startSignup,
  registerSignup, finishSignup, signupAssertion, successfulSignup};
