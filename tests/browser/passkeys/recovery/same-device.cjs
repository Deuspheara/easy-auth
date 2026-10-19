'use strict';
const assert = require('node:assert/strict');
const {withAuthenticator, post} = require('../browser.cjs');
const {profile, assertion, startLogin} = require('../assertions.cjs');
const {signupAssertion, successfulSignup} = require('../signup/ceremony.cjs');
const {setupCode, storageIsEmpty} = require('./setup.cjs');
const {startPage} = require('./cases.cjs');

async function sameDeviceRecovery(browser, origin, prepareClock) {
  const name = 'native-recovery-with-original-resident-authenticator';
  console.log(JSON.stringify({case: name, status: 'running'}));
  let credentialsAfter;
  let usernameChanged, displayNameChanged;
  try {
    await withAuthenticator(browser, origin, undefined, 'internal', async ({page, cdp, authenticatorId}) => {
      let pageErrors = 0;page.on('pageerror', () => {pageErrors += 1;});
      const signup = await signupAssertion(page);
      const owner = await successfulSignup(page, signup.pending, signup.assertionOptions,
        await assertion(page, signup.assertionOptions));
      const code = await setupCode(page, origin, owner.id);
      await startPage(page, origin, owner.id, code);
      const oldPending = await startLogin(page, 'account_bound', owner.id);
      const oldProof = await assertion(page, oldPending);
      const oldIssued = Date.now();
      // Keep the actual original resident authenticator and credential. Earlier
      // cases deliberately remove it to model complete device loss.
      const before = await cdp.send('WebAuthn.getCredentials', {authenticatorId});
      assert.equal(before.credentials.length, 1);
      const originalId = before.credentials[0].credentialId;
      await prepareClock(owner.id);
      await page.locator('#refresh').click();
      await page.waitForFunction(() => !document.getElementById('replace').disabled);
      let pendingOnlyChecked = false;
      await page.route('**/v1/passkeys/recovery/replacement/finish', async route => {
        await profile(page, 401);
        pendingOnlyChecked = true;
        await route.continue();
      }, {times: 1});
      const started = page.waitForResponse(response => response.url().endsWith('/v1/passkeys/recovery/replacement/start'));
      await page.locator('#replace-consent').check();
      await page.locator('#replace').click();
      const creation = await (await started).json();
      assert.equal(creation.options.publicKey.user.id, signup.pending.options.publicKey.user.id,
        'recovery preserves the original account user handle');
      const initial = signup.pending.options.publicKey;
      const replacement = creation.options.publicKey;
      usernameChanged = replacement.user.name !== initial.user.name;
      displayNameChanged = replacement.user.displayName !== initial.user.displayName;
      for (const field of ['rp', 'pubKeyCredParams', 'timeout', 'attestation', 'authenticatorSelection', 'extensions']) {
        assert.deepEqual(replacement[field], initial[field], `registration policy is unchanged: ${field}`);
      }
      assert.equal(creation.options.publicKey.excludeCredentials.length, 0,
        'replacement does not exclude the surviving provider credential');
      assert.equal(creation.options.publicKey.authenticatorSelection.residentKey, 'required');
      assert.equal(creation.options.publicKey.authenticatorSelection.userVerification, 'required');
      await page.waitForFunction(() => document.getElementById('status').textContent.startsWith('Recovery complete.'));
      assert.equal(pendingOnlyChecked, true, 'registration alone must leave the browser anonymous');
      const after = await cdp.send('WebAuthn.getCredentials', {authenticatorId});
      credentialsAfter = after.credentials.length;
      assert.equal(after.credentials.some(key => key.credentialId !== originalId), true,
        'the same authenticator must actually create a different credential');
      assert.equal(Date.now() - oldIssued < 110000, true, 'test infrastructure: old proof remains fresh');
      assert.equal((await post(page, '/v1/passkeys/authentication/finish', {
        transaction_id: oldPending.transaction_id, credential: oldProof
      })).status, 401, 'the original signed proof cannot survive replacement');
      assert.equal((await profile(page)).id, owner.id);
      assert.equal((await setupCode(page, origin, owner.id)) !== code, true);
      await storageIsEmpty(page);
      assert.equal(pageErrors, 0);
    });
  } catch (error) {error.caseName = name; throw error;}
  console.log(JSON.stringify({case: name, status: 'passed'}));
  return {name, status: 'passed', transport: 'internal', original_authenticator_retained: true,
    same_account_user_handle: true, username_changed_from_signup: usernameChanged,
    display_name_changed_from_signup: displayNameChanged, registration_policy_unchanged: true,
    resident_credentials_after: credentialsAfter, native_replacement_create_and_assert: true,
    stale_signed_proof_rejected: true, trusted_elapsed_time_fixture: true};
}
module.exports = {sameDeviceRecovery};
