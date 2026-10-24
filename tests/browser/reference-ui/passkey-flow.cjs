'use strict';
const assert = require('node:assert/strict');
const {withAuthenticator} = require('../passkeys/browser.cjs');

async function passkeyFlow(browser, origin, mail, guard) {
  return withAuthenticator(browser, origin, undefined, 'internal', async ({context, page, cdp, authenticatorId}) => {
    let stage = 'passkey-signup';
    const statuses = [];
    page.on('response', response => {
      const pathname = new URL(response.url()).pathname;
      if (pathname.startsWith('/v1/passkeys/')) statuses.push({path: pathname, status: response.status()});
    });
    try {
      await guard(context);
      await page.goto(origin);
      await page.locator('#clear-session').waitFor({state: 'visible'});
      await page.locator('details[data-cap="passkeySignup"] > summary').click();
      await page.locator('#display-name').fill('Reference native account');
      await page.getByRole('button', {name: 'Create and verify a passkey', exact: true}).click();
      await page.locator('#account').waitFor({state: 'visible'});
      await page.waitForFunction(() => document.getElementById('status').textContent.startsWith('Your account and verified passkey are ready.'));
      assert.equal(await page.locator('#mailbox-actions').isVisible(), false);
      assert.equal(await page.locator('#password-enrollment').isVisible(), false);
      await page.locator('#refresh-passkeys').click();
      await page.waitForFunction(() => document.querySelectorAll('#passkeys > li').length === 1);
      stage = 'passkey-enrollment-management';
      await cdp.send('WebAuthn.setAutomaticPresenceSimulation', {authenticatorId, enabled: false});
      const spareDevice = await cdp.send('WebAuthn.addVirtualAuthenticator', {options: {
        protocol: 'ctap2', transport: 'usb', hasResidentKey: true, hasUserVerification: true,
        isUserVerified: true, automaticPresenceSimulation: true
      }});
      await page.locator('#key-label').fill('Reference spare');
      await page.getByRole('button', {name: 'Add a passkey', exact: true}).click();
      await page.waitForFunction(() => document.querySelectorAll('#passkeys > li').length === 2);
      await cdp.send('WebAuthn.removeVirtualAuthenticator', {authenticatorId: spareDevice.authenticatorId});
      await cdp.send('WebAuthn.setAutomaticPresenceSimulation', {authenticatorId, enabled: true});
      const spare = page.locator('#passkeys > li').filter({has: page.getByText('Reference spare', {exact: true})});
      await spare.getByLabel('Passkey name', {exact: true}).fill('Reference renamed');
      await spare.getByRole('button', {name: 'Save name for Reference spare', exact: true}).click();
      await page.waitForFunction(() => document.getElementById('status').textContent === 'Passkey name updated.');
      await page.getByRole('button', {name: 'Remove Reference renamed', exact: true}).click();
      await page.getByRole('dialog').waitFor({state: 'visible'});
      await page.keyboard.press('Escape');
      await page.getByRole('dialog').waitFor({state: 'hidden'});
      assert.equal(await page.locator('#passkeys > li').count(), 2);
      await page.getByRole('button', {name: 'Remove Reference renamed', exact: true}).click();
      await page.locator('#confirmation-accept').click();
      await page.locator('#clear-session').waitFor({state: 'visible'});
      await page.waitForFunction(() => document.getElementById('status').textContent.startsWith('Passkey removed and sessions signed out.'));
      stage = 'passkey-signin-contact';
      await page.getByRole('button', {name: 'Sign in with a passkey', exact: true}).click();
      await page.waitForFunction(() => document.getElementById('status').textContent === 'Signed in with a passkey.');
      await page.locator('#attach-action > summary').click();
      const email = mail.recipient(3);
      await page.locator('#contact-email').fill(email);
      await page.getByRole('button', {name: 'Send contact confirmation', exact: true}).click();
      await page.waitForFunction(() => document.getElementById('status').textContent.startsWith('Check your contact email'));
      await page.goto(await mail.link(email, origin, 'Confirm contact email', '/email-attach'));
      await page.locator('#confirm').click();
      await page.waitForFunction(() => document.getElementById('status').textContent.startsWith('Contact email confirmed.'));
      assert.equal(new URL(page.url()).hash, '');
      await page.goto(origin);
      await page.locator('#account').waitFor({state: 'visible'});
      assert.equal((await page.locator('#identity').textContent()).includes(email), true);
      assert.equal(await page.locator('#mailbox-actions').isVisible(), false);
      assert.equal(await page.locator('#password-enrollment').isVisible(), false);
      assert.equal(await page.locator('#attach-action').isVisible(), false);
      assert.equal(await page.getByRole('link', {name: 'Save a recovery code or stop a recovery request'}).isVisible(), true);
      assert.equal(await page.evaluate(() => localStorage.length + sessionStorage.length), 0);
      for (const width of [320, 1440]) {
        await page.setViewportSize({width, height: 1000});
        assert.equal(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth), true);
        if (process.env.EASY_AUTH_UI_SCREENSHOT_DIR) {
          const path = require('node:path');
          await page.screenshot({path: path.join(process.env.EASY_AUTH_UI_SCREENSHOT_DIR, 'account-' + width + '.png'), fullPage: true});
        }
      }
      return {native_signup: true, enrollment: true, rename: true, removal: true, native_signin: true,
        verified_contact_preserves_strong_policy: true, recovery_setup_entry: true};
    } catch (error) { error.stageName = stage; error.uiObservations = {statuses}; throw error; }
  });
}
module.exports = {passkeyFlow};
