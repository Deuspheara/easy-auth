'use strict';
const {captureScreen} = require('../../reference-ui/capture.cjs');
const assert = require('node:assert/strict');
const {contrast} = require('../../reference-ui/presentation.cjs');

async function setupCode(page, origin, owner, options = {}) {
  await page.goto(origin + '/passkey-recovery/setup');
  if (options.signin) {
    await page.locator('#account').fill(owner);
    await page.getByRole('button', {name: 'Sign in with key', exact: true}).click();
    await page.waitForFunction(() => document.getElementById('status').textContent.startsWith('Passkey sign-in complete.'));
  }
  await page.waitForFunction(id => document.getElementById('owner').textContent === id, owner);
  await captureScreen(page, 'recovery-verify-signed-in');
  if (await page.locator('#use-session').isVisible()) await page.locator('#use-session').click();
  await captureScreen(page, 'recovery-prepare');
  assert.equal(await page.locator('#kit').isHidden(), true);
  await page.locator('#prepare-consent').check();
  await page.getByRole('button', {name: 'Prepare a new code', exact: true}).click();
  await page.locator('#kit').waitFor({state: 'visible'});
  if (options.navigation) {
    await page.goto(origin + '/passkey-recovery');
    await page.goBack();
    assert.equal(await page.locator('#saved-code').inputValue(), '', 'navigation clears displayed code');
    assert.equal(await page.locator('#kit').isHidden(), true);
    if (await page.locator('#use-session').isVisible()) await page.locator('#use-session').click();
  assert.equal(await page.locator('#kit').isHidden(), true);
  await page.locator('#prepare-consent').check();
    await page.getByRole('button', {name: 'Prepare a new code', exact: true}).click();
    await page.locator('#kit').waitFor({state: 'visible'});
  }
  await captureScreen(page, 'recovery-save-code-masked');
  const code = await page.locator('#saved-code').inputValue();
  assert.equal(/^[A-Za-z0-9_-]{43}$/.test(code), true, 'canonical code only in transient page/runner memory');
  await page.locator('#reentered-code').fill(code);
  await page.locator('#saved-consent').check();
  await page.getByRole('button', {name: 'Confirm saved code', exact: true}).click();
  await page.waitForFunction(() => document.getElementById('status').textContent.startsWith('Saved code confirmed.'));
  assert.equal(await page.locator('#saved-code').inputValue(), '');
  assert.equal(await page.locator('#reentered-code').inputValue(), '');
  assert.equal(await page.locator('#kit').isHidden(), true);
  assert.equal(await page.locator('#setup-state').textContent(), 'Confirmed');
  const colors = await page.locator('[data-setup-step="3"] a').evaluate(node => {
    const style = getComputedStyle(node); return {ink: style.color, surface: style.backgroundColor};
  });
  assert.equal(contrast(colors.ink, colors.surface) >= 4.5, true, 'primary navigation contrast');
  if (process.env.EASY_AUTH_UI_SCREENSHOT_DIR) {
    const path = require('node:path');
    for (const scheme of ['light', 'dark']) {
      await page.emulateMedia({colorScheme: scheme});
      for (const width of [320, 1440]) {
        await page.setViewportSize({width, height: 1000});
        await page.screenshot({animations: 'disabled', path: path.join(process.env.EASY_AUTH_UI_SCREENSHOT_DIR, `recovery-confirmed-${scheme}-${width}.png`), fullPage: true});
      }
    }
  }
  return code;
}
async function storageIsEmpty(page) {
  assert.equal(await page.evaluate(() => localStorage.length === 0 && sessionStorage.length === 0), true);
  assert.equal(new URL(page.url()).search + new URL(page.url()).hash, '', 'no proof in page URL');
}
module.exports = {setupCode, storageIsEmpty};
