'use strict';
const assert = require('node:assert/strict');
const {withAuthenticator, post} = require('../browser.cjs');
const {profile, assertion, startLogin} = require('../assertions.cjs');
const {signupAssertion, successfulSignup} = require('../signup/ceremony.cjs');
const {confirmContact} = require('../attachment/contact.cjs');
const {setupCode, storageIsEmpty} = require('./setup.cjs');
const {cancellations} = require('./cancellation.cjs');

async function ownerWithContact(browser, page, context, mail, origin, index, verified) {
  const {pending, assertionOptions} = await signupAssertion(page);
  const owner = await successfulSignup(page, pending, assertionOptions, await assertion(page, assertionOptions));
  const address = mail.recipient(100 + index);
  if (verified) {
    const peer = await browser.newContext();
    try {
      await peer.addCookies([(await context.cookies()).find(cookie => cookie.name === 'auth-session')]);
      await confirmContact(page, context, peer, mail, origin, address);
    } finally { await peer.close(); }
  }
  return {owner, address};
}
async function startPage(page, origin, owner, code, lost = false) {
  await page.goto(origin + '/passkey-recovery');
  await page.locator('#logout').click();
  await page.waitForFunction(() => document.getElementById('status').textContent.startsWith('Signed out in this browser.'));
  await page.locator('#account').fill(owner);
  await page.locator('#code').fill(code);
  if (lost) {
    let attempted = 0;
    const observed = request => { if (request.url().endsWith('/v1/passkeys/recovery/browser')) attempted += 1; };
    page.on('request', observed);
    await page.getByRole('button', {name: 'Start recovery request', exact: true}).click();
    assert.equal(await page.locator('#consume-consent').evaluate(input => input.validity.valueMissing), true);
    assert.equal(attempted, 0, 'no prebinding or consumption before explicit consent');
    page.off('request', observed);
    await page.locator('#consume-consent').check();await page.locator('#account').fill('invalid');
    await page.getByRole('button', {name: 'Start recovery request', exact: true}).click();
    await page.waitForFunction(() => document.getElementById('status').textContent.startsWith('The operation was not confirmed.'));
    assert.equal(await page.locator('#code').inputValue(), '', 'invalid account input also clears code');
    await page.locator('#account').fill(owner);await page.locator('#code').fill(code);
    let redirected = 0;
    const redirectObserved = request => { if (request.url() === origin + '/healthz' && request.method() === 'POST') redirected += 1; };
    page.on('request', redirectObserved);
    await page.route('**/v1/passkeys/recovery/claims/start', route => route.fulfill({status: 307, headers: {location: origin + '/healthz'}}), {times: 1});
    await page.getByRole('button', {name: 'Start recovery request', exact: true}).click();
    await page.waitForFunction(() => document.getElementById('status').textContent.startsWith('The operation was not confirmed.'));
    assert.equal(redirected, 0, 'proof-bearing requests cannot follow unexpected redirects');
    assert.equal(await page.locator('#code').inputValue(), '');page.off('request', redirectObserved);
    await page.locator('#code').fill(code);
  }
  if (lost) await page.route('**/v1/passkeys/recovery/claims/start', async route => {
    assert.equal((await route.fetch()).status(), 200);
    await route.fulfill({status: 503, headers: {'content-type': 'application/json'}, body: '{"code":"temporarily_unavailable"}'});
  }, {times: 1});
  await page.locator('#consume-consent').check();
  await page.getByRole('button', {name: 'Start recovery request', exact: true}).click();
  if (lost) await page.waitForFunction(() => document.getElementById('status').textContent.startsWith('The operation was not confirmed.'));
  else await page.waitForFunction(() => document.getElementById('status').textContent.startsWith('Request reserved.'));
  assert.equal(await page.locator('#code').inputValue(), '');
  return (await page.context().cookies()).find(cookie => cookie.name === 'auth-passkey-recovery');
}
async function runPages(browser, origin, mail, prepareClock) {
  const results = [];
  const modes = [['internal', false], ['internal', true], ['usb', false], ['usb', true]];
  for (const [index, [transport, verified]] of modes.entries()) {
    const name = `native-recovery-pages-${transport}-${verified ? 'contact' : 'email-free'}`;
    console.log(JSON.stringify({case: name, status: 'running'}));
    let stage = 'signup';
    try {
      await withAuthenticator(browser, origin, undefined, transport, async ({page, context, cdp, authenticatorId}) => {
        let pageErrors = 0;page.on('pageerror', () => {pageErrors += 1;});
        const {owner, address} = await ownerWithContact(browser, page, context, mail, origin, index, verified);
        stage = 'reference_setup';
        const code = await setupCode(page, origin, owner.id, {navigation: index === 0});
        if (verified) await mail.recoveryEvent(address, 'changed');
        stage = 'claim_and_lost_start_response';
        const binding = await startPage(page, origin, owner.id, code, index === 0);
        assert.equal(Boolean(binding?.httpOnly && binding.sameSite === 'Lax'), true);
        // Real old-key proof is issued AFTER logout, then held uncommitted.
        const oldPending = await startLogin(page, 'account_bound', owner.id);
        const oldProof = await assertion(page, oldPending);
        const oldIssued = Date.now();
        await cdp.send('WebAuthn.removeVirtualAuthenticator', {authenticatorId});
        await cdp.send('WebAuthn.addVirtualAuthenticator', {options: {protocol: 'ctap2', transport,
          hasResidentKey: true, hasUserVerification: true, isUserVerified: true, automaticPresenceSimulation: true}});
        await page.reload(); await page.locator('#account').fill(owner.id);
        const resumed = page.waitForResponse(response => response.url().endsWith('/v1/passkeys/recovery/claims/resume'));
        await page.locator('#resume').click();
        const originalTiming = await (await resumed).json();
        assert.equal(originalTiming.notification_required, verified);
        await page.waitForFunction(() => document.getElementById('status').textContent.startsWith('Original request resumed'));
        assert.equal(await page.locator('#replace').isDisabled(), true);
        if (index === 0) {
          // A modified button is no authority: the server must still reject early completion.
          await page.locator('#replace-consent').check();
          await page.locator('#replace').evaluate(button => { button.disabled = false; });
          await page.locator('#replace').click();
          await page.waitForFunction(() => document.getElementById('status').textContent.startsWith('Not authorized.'));
          const peer = await browser.newContext();
          try {
            const denied = await peer.request.post(origin + '/v1/passkeys/recovery/claims/resume', {headers: {Origin: origin}, data: {account_id: owner.id}});
            assert.equal(denied.status(), 401, 'other browser cannot resume a reserved code');
          } finally { await peer.close(); }
        }
        stage = 'actual_notice_receipt_and_clock_fixture';
        if (verified) await mail.recoveryEvent(address, 'started');
        await prepareClock(owner.id);
        const refreshed = page.waitForResponse(response => response.url().endsWith('/v1/passkeys/recovery/claims/status'));
        await page.locator('#refresh').click();
        const readyTiming = await (await refreshed).json();
        assert.equal(readyTiming.expires_at_ms, originalTiming.expires_at_ms, 'clock fixture cannot extend original expiry');
        assert.equal(readyTiming.ready, true);
        await page.waitForFunction(() => !document.getElementById('replace').disabled);
        stage = 'replacement_native_create_and_assert';
        if (index === 3) await page.route('**/v1/passkeys/recovery/replacement/finish', async route => {
          assert.equal((await route.fetch()).status(), 204);
          // Discard the successful transport response/cookie, not any server proof.
          await context.clearCookies({name: 'auth-session'});
          await route.fulfill({status: 503, headers: {'content-type': 'application/json'}, body: '{"code":"temporarily_unavailable"}'});
        }, {times: 1});
        await page.locator('#replace-consent').check();
        await page.locator('#replace').click();
        await page.waitForFunction(lost => document.getElementById('status').textContent.startsWith(lost ? 'The operation was not confirmed.' : 'Recovery complete.'), index === 3);
        if (verified) await mail.recoveryEvent(address, 'completed');
        assert.equal(Date.now() - oldIssued < 110000, true, 'test infrastructure: old proof remains within its original two-minute lifetime');
        assert.equal((await post(page, '/v1/passkeys/authentication/finish', {transaction_id: oldPending.transaction_id, credential: oldProof})).status, 401, 'old genuine signed proof cannot survive replacement');
        stage = 'replacement_signin_and_new_saved_code';
        const next = await setupCode(page, origin, owner.id, {signin: index === 3});
        assert.equal(next !== code, true);
        const current = await profile(page);assert.equal(current.id, owner.id);assert.equal(current.email === (verified ? address : null), true);
        if (verified) await mail.recoveryEvent(address, 'changed', 2);
        await storageIsEmpty(page);
        assert.equal(pageErrors, 0, 'no unhandled page errors');
      });
    } catch (error) {error.caseName = name; error.stageName = stage; throw error;}
    results.push({name, transport, verified_contact: verified, status: 'passed', original_keys_unavailable: true,
      native_replacement_create_and_assert: true, stale_signed_proof_rejected: true,
      trusted_elapsed_time_fixture: true, lost_start_response: index === 0, lost_finish_response: index === 3});
    console.log(JSON.stringify({case: name, status: 'passed'}));
  }
  results.push(...await cancellations(browser, origin, mail, ownerWithContact, startPage));
  return results;
}
module.exports = {runPages, startPage};
