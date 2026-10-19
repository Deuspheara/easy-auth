'use strict';
const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const {post} = require('../browser.cjs');
const {profile} = require('../assertions.cjs');
const START = '/v1/account/email/attachment/start';
const FINISH = '/v1/account/email/attachment/finish';

async function confirmContact(page, context, peer, mail, origin, address) {
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

module.exports = {confirmContact};
