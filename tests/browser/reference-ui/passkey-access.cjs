'use strict';
const assert = require('node:assert/strict');
const {withAuthenticator} = require('../passkeys/browser.cjs');

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
    await page.getByRole('dialog').waitFor({state: 'visible'});
    assert.equal(statuses.at(-1), 401, 'real mailbox session does not confer fresh passkey access');
    await page.getByRole('button', {name: 'Cancel', exact: true}).click();
    await page.waitForFunction(() => document.getElementById('passkeys-state').textContent.startsWith('Verification cancelled.'));
    assert.equal(logouts.length, 0, 'cancel preserves the original sign-in');
    assert.equal(await page.locator('#account-id').textContent(), owner);
    await page.locator('#add-passkey').click();
    await page.locator('#key-label').fill('Account security key');
    await page.getByRole('button', {name: 'Add a passkey', exact: true}).click();
    await page.waitForFunction(() => document.getElementById('status').textContent.startsWith('Passkey added.'));
    await page.locator('#retry-passkeys').click();
    await page.getByRole('dialog').waitFor({state: 'visible'});
    await page.getByRole('button', {name: 'Verify with passkey', exact: true}).click();
    await page.waitForFunction(() => document.querySelectorAll('#passkeys > li').length === 1);
    assert.equal(logouts.length, 1, 'only confirmed verification replaces this browser session');
    assert.equal(logouts[0], 204);
    assert.equal(statuses.at(-1), 200);
    assert.equal(await page.locator('#account-id').textContent(), owner, 'account-bound native verification preserves the owner');
    assert.equal(await page.getByRole('heading', {name: 'Account security key', exact: true}).isVisible(), true);
    assert.equal(await page.evaluate(() => localStorage.length + sessionStorage.length), 0);
    return {real_freshness_denial: true, cancel_preserves_session: true,
      explicit_native_verification: true, same_owner: true, passkeys_displayed: true};
  });
}
module.exports = {passkeyAccess};
