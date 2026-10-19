'use strict';
const assert = require('node:assert/strict');
const {withAuthenticator} = require('../browser.cjs');
const {profile} = require('../assertions.cjs');
const {setupCode, storageIsEmpty} = require('./setup.cjs');

async function manualBootstrap(browser, origin) {
  const name = 'native-owned-manual-signup-bootstrap';
  console.log(JSON.stringify({case: name, status: 'running'}));
  try {
    await withAuthenticator(browser, origin, undefined, 'internal', async ({page}) => {
      let pageErrors = 0;
      let starts = 0;
      page.on('pageerror', () => {pageErrors += 1;});
      page.on('request', request => {
        if (request.url().endsWith('/v1/passkeys/signup/start')) starts += 1;
      });
      const response = await page.goto(origin + '/fixture/passkey-signup');
      assert.equal(response.status(), 200);
      const headers = response.headers();
      assert.equal(headers['cache-control'], 'no-store');
      assert.equal(headers['referrer-policy'], 'no-referrer');
      assert.equal(headers['x-content-type-options'], 'nosniff');
      assert.equal(headers['content-security-policy'].includes("frame-ancestors 'none'"), true);
      assert.equal(headers['set-cookie'], undefined, 'static fixture page creates no cookie');
      await profile(page, 401);
      await page.waitForFunction(() => document.getElementById('status').textContent.startsWith('Ready for actual'));
      await page.getByRole('button', {name: 'Create disposable passkey account', exact: true}).click();
      assert.equal(await page.locator('#consent').evaluate(input => input.validity.valueMissing), true);
      assert.equal(starts, 0, 'no signup starts before deliberate test consent');
      await page.locator('#consent').check();
      await page.getByRole('button', {name: 'Create disposable passkey account', exact: true}).click();
      await page.waitForFunction(() => document.getElementById('status').textContent.startsWith('Actual registration and signed assertion succeeded.'));
      const owner = await profile(page);
      assert.equal(owner.display_name, 'AUTH-20 device test');
      assert.equal(owner.email, null);
      assert.equal(await page.locator('#owner').textContent(), owner.id);
      assert.equal(starts, 1);
      // Actual assertion authority must also satisfy the production code-setup path.
      await setupCode(page, origin, owner.id);
      await storageIsEmpty(page);
      assert.equal(pageErrors, 0);
    });
  } catch (error) {error.caseName = name; throw error;}
  console.log(JSON.stringify({case: name, status: 'passed'}));
  return {name, transport: 'internal', verified_contact: false, status: 'passed',
    native_signup_create_and_assert: true, confirmed_saved_code: true};
}
module.exports = {manualBootstrap};
