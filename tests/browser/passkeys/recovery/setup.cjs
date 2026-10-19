'use strict';
const assert = require('node:assert/strict');

async function setupCode(page, origin, owner, options = {}) {
  await page.goto(origin + '/passkey-recovery/setup');
  if (options.signin) {
    await page.locator('#account').fill(owner);
    await page.getByRole('button', {name: 'Sign in with key', exact: true}).click();
    await page.waitForFunction(() => document.getElementById('status').textContent.startsWith('Passkey sign-in complete.'));
  }
  await page.waitForFunction(id => document.getElementById('owner').textContent === id, owner);
  await page.locator('#prepare-consent').check();
  await page.getByRole('button', {name: 'Prepare a new code', exact: true}).click();
  await page.locator('#kit').waitFor({state: 'visible'});
  if (options.navigation) {
    await page.goto(origin + '/passkey-recovery');
    await page.goBack();
    assert.equal(await page.locator('#saved-code').inputValue(), '', 'navigation clears displayed code');
    assert.equal(await page.locator('#kit').isHidden(), true);
    await page.locator('#prepare-consent').check();
    await page.getByRole('button', {name: 'Prepare a new code', exact: true}).click();
    await page.locator('#kit').waitFor({state: 'visible'});
  }
  const code = await page.locator('#saved-code').inputValue();
  assert.equal(/^[A-Za-z0-9_-]{43}$/.test(code), true, 'canonical code only in transient page/runner memory');
  await page.locator('#reentered-code').fill(code);
  await page.locator('#saved-consent').check();
  await page.getByRole('button', {name: 'Confirm saved code', exact: true}).click();
  await page.waitForFunction(() => document.getElementById('status').textContent.startsWith('Saved code confirmed.'));
  assert.equal(await page.locator('#saved-code').inputValue(), '');
  assert.equal(await page.locator('#reentered-code').inputValue(), '');
  assert.equal(await page.locator('#kit').isHidden(), true);
  return code;
}
async function storageIsEmpty(page) {
  assert.equal(await page.evaluate(() => localStorage.length === 0 && sessionStorage.length === 0), true);
  assert.equal(new URL(page.url()).search + new URL(page.url()).hash, '', 'no proof in page URL');
}
module.exports = {setupCode, storageIsEmpty};
