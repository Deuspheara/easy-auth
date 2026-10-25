'use strict';
const assert = require('node:assert/strict');
const {withAuthenticator} = require('../passkeys/browser.cjs');
const {passkeyInvalidation} = require('./passkey-invalidation.cjs');

async function passkeyAccess(browser, origin, mail, guard) {
  return withAuthenticator(browser, origin, undefined, 'internal', async ({context, page}) => {
    await guard(context);
    const statuses = [], logouts = [];
    page.on('response', response => {
      if (new URL(response.url()).pathname === '/v1/passkeys') statuses.push(response.status());
      if (new URL(response.url()).pathname === '/v1/logout') logouts.push(response.status());
    });
    const email = mail.recipient(8);
    await page.goto(origin);
    await page.locator('#email').fill(email);
    await page.locator('#submit').click();
    await page.waitForFunction(() => document.getElementById('status').textContent.startsWith('Check your email.'));
    await page.goto(await mail.link(email, origin, 'Your sign-in link', '/'));
    await page.locator('#account').waitFor({state: 'visible'});
    const owner = await page.locator('#account-id').textContent();
    await page.locator('#refresh-passkeys').click();
    await page.waitForFunction(() => !document.querySelector('[aria-busy="true"]'));
    assert.equal(await page.getByRole('dialog').isVisible(), false, 'opening Passkeys never starts sign-out verification');
    assert.equal(logouts.length, 0, 'opening Passkeys preserves the current sign-in');
    assert.equal(await page.locator('#retry-passkeys').textContent(), 'Verify access');
    assert.match(await page.locator('#passkeys-state').textContent(), /Verify access with a passkey/);
    await page.locator('#retry-passkeys').click();
    await page.getByRole('dialog').waitFor({state: 'visible'});
    assert.equal(await page.locator('#account-back').isDisabled(), true, 'return navigation stays disabled during protected verification');
    assert.equal(statuses.at(-1), 401, 'real mailbox session does not confer fresh passkey access');
    await page.getByRole('button', {name: 'Cancel', exact: true}).click();
    await page.waitForFunction(() => document.getElementById('passkeys-state').textContent.startsWith('Verification cancelled.'));
    assert.equal(logouts.length, 0, 'cancel preserves the original sign-in');
    assert.equal(await page.locator('#account-id').textContent(), owner);
    await page.locator('#add-passkey').click();
    await page.locator('#key-label').fill('Account security key');
    await page.getByRole('button', {name: 'Add a passkey', exact: true}).click();
    await page.waitForFunction(() => document.getElementById('status').textContent.startsWith('Passkey added.'));
    assert.match(await page.locator('#status').textContent(), /Verify access to view and manage/);
    assert.equal(await page.getByRole('dialog').isVisible(), false, 'accepted addition never starts sign-out verification');
    assert.equal(logouts.length, 0, 'adding a key preserves the current sign-in');
    await page.locator('#retry-passkeys').click();
    await page.getByRole('dialog').waitFor({state: 'visible'});
    let starts = 0;
    const observeStart = request => { if (new URL(request.url()).pathname === '/v1/passkeys/authentication/start') starts += 1; };
    page.on('request', observeStart);
    await page.getByRole('button', {name: 'Sign out and continue', exact: true}).click();
    await page.locator('#account-passkey-form').waitFor({state: 'visible'});
    assert.equal(await page.locator('#passkey-account').inputValue(), owner, 'verification retains the selected public account ID');
    assert.equal(await page.locator('#heading').textContent(), 'Verify your passkey');
    assert.equal(starts, 0, 'confirmation and sign-out do not automatically open a native prompt');
    await page.evaluate(() => {
      const original = navigator.credentials.get.bind(navigator.credentials);
      navigator.credentials.get = async () => {
        navigator.credentials.get = original;
        throw new DOMException('private-provider-detail', 'NotAllowedError');
      };
    });
    await page.getByRole('button', {name: 'Continue with your passkey', exact: true}).click();
    await page.waitForFunction(() => document.getElementById('status').textContent.startsWith('Passkey verification was not completed.'));
    assert.equal(await page.locator('#status').isVisible(), true);
    assert.equal((await page.locator('#status').textContent()).includes('private-provider-detail'), false);
    assert.equal(await page.locator('#passkey-account').inputValue(), owner, 'a cancelled prompt retains account-bound retry');
    await page.getByRole('button', {name: 'Continue with your passkey', exact: true}).click();
    await page.waitForFunction(() => document.querySelectorAll('#passkeys > li').length === 1);
    page.off('request', observeStart);
    assert.equal(starts, 2, 'each explicit attempt starts its own server-bound challenge');
    assert.equal(logouts.length, 1, 'only confirmed verification replaces this browser session');
    assert.equal(logouts[0], 204);
    assert.equal(statuses.at(-1), 200);
    assert.equal(await page.locator('#account-id').textContent(), owner, 'account-bound native verification preserves the owner');
    assert.equal(await page.getByRole('heading', {name: 'Account security key', exact: true}).isVisible(), true);
    await passkeyInvalidation(page);
    assert.equal(await page.evaluate(() => localStorage.length + sessionStorage.length), 0);
    return {no_automatic_verification: true, accepted_addition_explained: true, real_freshness_denial: true, cancel_preserves_session: true,
      explicit_native_verification: true, prompt_retry_retains_account: true, fresh_click_for_native_prompt: true, same_owner: true, passkeys_displayed: true,
      inventory_invalidation: true};
  });
}
module.exports = {passkeyAccess};
