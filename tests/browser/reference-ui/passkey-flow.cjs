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
      await page.waitForFunction(() => document.getElementById('clear-session').hidden === false);
      await page.getByRole('link', {name: 'Create an account', exact: true}).click();
      await page.locator('#display-name').fill('Alex Morgan');
      await page.getByRole('button', {name: 'Create and verify a passkey', exact: true}).click();
      await page.locator('#account').waitFor({state: 'visible'});
      await page.waitForFunction(() => document.getElementById('status').textContent.startsWith('Account created. Your passkey is ready.'));
      assert.notEqual(await page.locator('#mailbox-actions').getAttribute('hidden'), null);
      assert.equal(await page.locator('#password-enrollment').isVisible(), false);
      await page.locator('#refresh-passkeys').click();
      await page.waitForFunction(() => document.querySelectorAll('#passkeys > li').length === 1);
      if (process.env.EASY_AUTH_UI_SCREENSHOT_DIR) {
        const path = require('node:path');
        await page.evaluate(() => document.fonts.ready);
        for (const scheme of ['light', 'dark']) {
          await page.emulateMedia({colorScheme: scheme});
          for (const width of [320, 1440]) {
            await page.setViewportSize({width, height: 1000});
            assert.equal(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth), true);
            await page.screenshot({path: path.join(process.env.EASY_AUTH_UI_SCREENSHOT_DIR,
              'passkeys-' + scheme + '-' + width + '.png'), fullPage: true});
          }
        }
      }
      const retainedAccountId = await page.locator('#account-id').textContent();
      stage = 'passkey-enrollment-management';
      await cdp.send('WebAuthn.setAutomaticPresenceSimulation', {authenticatorId, enabled: false});
      const spareDevice = await cdp.send('WebAuthn.addVirtualAuthenticator', {options: {
        protocol: 'ctap2', transport: 'usb', hasResidentKey: true, hasUserVerification: true,
        isUserVerified: true, automaticPresenceSimulation: true
      }});
      await page.locator('#add-passkey').click();
      await page.locator('#key-label').fill('Reference spare');
      await page.getByRole('button', {name: 'Add a passkey', exact: true}).click();
      await page.waitForFunction(() => document.querySelectorAll('#passkeys > li').length === 2);
      await cdp.send('WebAuthn.removeVirtualAuthenticator', {authenticatorId: spareDevice.authenticatorId});
      await cdp.send('WebAuthn.setAutomaticPresenceSimulation', {authenticatorId, enabled: true});
      const spare = page.locator('#passkeys > li').filter({has: page.getByText('Reference spare', {exact: true})});
      await spare.getByRole('button', {name: 'Rename Reference spare', exact: true}).click();
      await spare.getByLabel('Passkey name', {exact: true}).fill('Reference renamed');
      await spare.getByRole('button', {name: 'Save name for Reference spare', exact: true}).click();
      await page.waitForFunction(() => document.getElementById('status').textContent === 'Passkey name updated.');
      assert.equal(await page.getByRole('button', {name: 'Remove Reference renamed', exact: true}).isVisible(), true);
      await page.getByRole('button', {name: 'Remove Reference renamed', exact: true}).click();
      await page.getByRole('dialog').waitFor({state: 'visible'});
      await page.keyboard.press('Escape');
      await page.getByRole('dialog').waitFor({state: 'hidden'});
      assert.equal(await page.locator('#passkeys > li').count(), 2);
      await page.getByRole('button', {name: 'Remove Reference renamed', exact: true}).click();
      await page.locator('#confirmation-accept').click();
      await page.waitForFunction(() => document.getElementById('clear-session').hidden === false);
      await page.waitForFunction(() => document.getElementById('status').textContent.startsWith('Passkey removed and sessions signed out.'));
      stage = 'passkey-signin-contact';
      await page.getByRole('button', {name: 'Sign in with a passkey', exact: true}).click();
      await page.waitForFunction(() => document.getElementById('status').textContent === 'Signed in with a passkey.');
      await page.getByRole('button', {name: 'Details', exact: true}).click();
      await page.getByRole('button', {name: 'Add contact email', exact: true}).click();
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
      assert.notEqual(await page.locator('#mailbox-actions').getAttribute('hidden'), null);
      assert.equal(await page.locator('#password-enrollment').isVisible(), false);
      assert.equal(await page.locator('#attach-action').isVisible(), false);
      assert.equal(await page.getByRole('link', {name: 'Recovery options', exact: true}).isVisible(), true);
      assert.equal(await page.evaluate(() => localStorage.length + sessionStorage.length), 0);
      stage = 'account-bound-passkey-signin';
      await page.locator('#logout').click();
      await page.waitForFunction(() => document.getElementById('status').textContent === 'Signed out in this browser.');
      await page.getByRole('link', {name: 'Trouble signing in?', exact: true}).click();
      await page.getByRole('link', {name: /Find a passkey with your account ID/}).click();
      await page.locator('#passkey-account').fill(retainedAccountId);
      await page.getByRole('button', {name: 'Continue with your passkey', exact: true}).click();
      await page.waitForFunction(() => document.getElementById('status').textContent === 'Signed in with a passkey.');
      assert.equal(await page.locator('#account-id').textContent(), retainedAccountId);
      assert.notEqual(await page.locator('#mailbox-actions').getAttribute('hidden'), null);
      await page.waitForFunction(() => document.querySelectorAll('#sessions > li').length === 1 &&
        document.getElementById('providers-card').dataset.loaded === 'true');
      await page.waitForFunction(() => document.getElementById('status').textContent === '');
      await page.evaluate(() => document.fonts.ready);
      for (const scheme of ['light', 'dark']) {
        await page.emulateMedia({colorScheme: scheme});
        for (const width of [320, 1440]) {
          await page.setViewportSize({width, height: 1000});
          assert.equal(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth), true);
          if (process.env.EASY_AUTH_UI_SCREENSHOT_DIR) {
            const path = require('node:path');
            await page.screenshot({path: path.join(process.env.EASY_AUTH_UI_SCREENSHOT_DIR, 'account-' + scheme + '-' + width + '.png'), fullPage: true});
          }
        }
        await page.setViewportSize({width: 320, height: 844});
        await page.evaluate(() => { document.documentElement.style.fontSize = '200%'; });
        assert.equal(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth), true);
        if (process.env.EASY_AUTH_UI_SCREENSHOT_DIR) {
          const path = require('node:path');
          await page.screenshot({path: path.join(process.env.EASY_AUTH_UI_SCREENSHOT_DIR, 'account-' + scheme + '-320-text200.png'), fullPage: true});
        }
        await page.evaluate(() => { document.documentElement.style.removeProperty('font-size'); });
      }
      return {native_signup: true, enrollment: true, rename: true, removal: true, native_signin: true, account_bound_signin: true,
        verified_contact_preserves_strong_policy: true, recovery_setup_entry: true};
    } catch (error) { error.stageName = stage; error.uiObservations = {statuses}; throw error; }
  });
}
module.exports = {passkeyFlow};
