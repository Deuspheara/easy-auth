'use strict';
const assert = require('node:assert/strict');
const {withAuthenticator} = require('../browser.cjs');
const {profile} = require('../assertions.cjs');
const {setupCode, storageIsEmpty} = require('./setup.cjs');

async function cancellations(browser, origin, mail, ownerWithContact, startPage) {
  const results = [];
  for (const [index, kind] of ['browser', 'code', 'key'].entries()) {
    const name = `native-recovery-page-cancellation-${kind}`;
    console.log(JSON.stringify({case: name, status: 'running'}));
    try {
      await withAuthenticator(browser, origin, undefined, 'usb', async ({page, context}) => {
        let pageErrors = 0;page.on('pageerror', () => {pageErrors += 1;});
        const verified = kind === 'key';
        const {owner, address} = await ownerWithContact(browser, page, context, mail, origin, index + 10, verified);
        const code = await setupCode(page, origin, owner.id);
        if (verified) await mail.recoveryEvent(address, 'changed');
        await startPage(page, origin, owner.id, code);
        if (verified) await mail.recoveryEvent(address, 'started');
        if (kind === 'key') {
          await page.goto(origin + '/passkey-recovery/setup');
          await page.locator('#account').fill(owner.id);
          await page.getByRole('button', {name: 'Sign in with key', exact: true}).click();
          await page.waitForFunction(() => document.getElementById('status').textContent.startsWith('Passkey sign-in complete.'));
          await page.locator('#cancel-consent').check();
          await page.getByRole('button', {name: 'Cancel current recovery', exact: true}).click();
          await page.waitForFunction(() => document.getElementById('status').textContent.startsWith('Current recovery cancelled.'));
          assert.equal((await profile(page)).id, owner.id);
          await mail.recoveryEvent(address, 'cancelled');
        } else if (kind === 'browser') {
          await page.locator('#browser-cancel-consent').check();
          await page.getByRole('button', {name: "Cancel this browser's request", exact: true}).click();
          await page.waitForFunction(() => document.getElementById('status').textContent.startsWith('Request cancelled.'));
          await profile(page, 401);
        } else {
          const peer = await browser.newContext();
          try {
            const other = await peer.newPage();await other.goto(origin + '/passkey-recovery');
            await other.locator('#account').fill(owner.id);await other.locator('#cancel-code').fill(code);
            await other.locator('#code-cancel-consent').check();
            await other.getByRole('button', {name: 'Cancel with retained code', exact: true}).click();
            await other.waitForFunction(() => document.getElementById('status').textContent.startsWith('Current request cancelled.'));
            await profile(other, 401);await storageIsEmpty(other);
          } finally {await peer.close();}
        }
        await storageIsEmpty(page);assert.equal(pageErrors, 0, 'no unhandled cancellation page errors');
      });
    } catch (error) {error.caseName = name;error.stageName = 'reference_cancellation';throw error;}
    results.push({name, status: 'passed', native_signup: true, cancellation: kind, no_recovery_grant: true});
    console.log(JSON.stringify({case: name, status: 'passed'}));
  }
  return results;
}
module.exports = {cancellations};
