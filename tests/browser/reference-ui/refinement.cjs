'use strict';
const {captureScreen} = require('./capture.cjs');
const assert = require('node:assert/strict');
async function sharedLayout(page, origin) {
  for (const route of ['/', '/reset', '/passkey-recovery/setup', '/passkey-recovery']) {
    await page.goto(origin + route);
    await page.setViewportSize({width: 1440, height: 1000});
    assert.equal(await page.locator('main').evaluate(node => node.getBoundingClientRect().width), ['/', '/reset'].includes(route) ? 400 : 660, 'compact auth and shared account columns');
    assert.equal(await page.locator('.settings-search:visible').count(), 0, 'anonymous pages have no settings search');
    await captureScreen(page, ({'/reset': 'reset-unavailable', '/passkey-recovery/setup': 'recovery-verify-anonymous', '/passkey-recovery': 'recovery-start'})[route] || 'email-signin');
    if (route.includes('passkey-recovery')) {
      const info = page.locator('.recovery-help > button');
      await info.click();
      assert.equal(await info.getAttribute('aria-expanded'), 'true');
      await page.keyboard.press('Escape');
      assert.equal(await info.getAttribute('aria-expanded'), 'false');
      assert.equal(await info.evaluate(node => node === document.activeElement), true);
      for (const scheme of ['light', 'dark']) {
        await page.emulateMedia({colorScheme: scheme});
        await page.setViewportSize({width: 320, height: 844});
        await info.click();
        await page.evaluate(() => Promise.all(document.getAnimations().map(animation => animation.finished.catch(() => {}))));
        const bounds = await page.locator('[data-popover]').boundingBox();
        assert.equal(bounds.x >= 0 && bounds.x + bounds.width <= 320, true, 'help stays inside viewport');
        await page.keyboard.press('Escape');
        await page.evaluate(() => document.documentElement.style.fontSize = '200%');
        await info.click();
        await page.evaluate(() => Promise.all(document.getAnimations().map(animation => animation.finished.catch(() => {}))));
        const enlarged = await page.locator('[data-popover]').boundingBox();
        assert.equal(enlarged.x >= 0 && enlarged.x + enlarged.width <= 320, true, 'enlarged help stays inside viewport');
        await page.keyboard.press('Escape');
        assert.equal(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth), true);
        await page.evaluate(() => document.documentElement.style.removeProperty('font-size'));
      }
    }
  }
  await page.goto(origin);
  const matrix = await page.evaluate(async () => {
    const {settingsDestinations} = await import('/ui/settings-search.js');
    const ids = (policy, caps) => settingsDestinations({authentication_policy: policy}, caps).map(item => item.id);
    return [ids('mailbox', {}), ids('provider_required', {passwords: true, passkeyManagement: true, recoverySetup: true}), ids('passkey_required', {passwords: true, passkeyManagement: true, recoverySetup: true})];
  });
  assert.deepEqual(matrix, [['profile', 'sessions'], ['profile', 'sessions', 'providers'], ['profile', 'passkeys', 'sessions', 'recovery']]);
  await page.locator('#email').focus();
  assert.equal(await page.locator('#email').evaluate(node => getComputedStyle(node).outlineStyle), 'none', 'Basecoat input has no extra app outline');
  assert.notEqual(await page.locator('#email').evaluate(node => getComputedStyle(node).boxShadow), 'none', 'Basecoat supplies the input focus ring');
  await page.locator('#submit').click();
  assert.equal(await page.locator('#email').getAttribute('aria-invalid'), 'true');
  assert.equal(await page.locator('#email-error').textContent(), 'Enter email address.');
  assert.equal(await page.locator('#email').evaluate(node => node === document.activeElement), true);
  await page.locator('#email').fill('test@example.invalid');
  assert.equal(await page.locator('#email-error').count(), 0);
  await page.goto(origin);
}
async function settingsSearch(page, passwordAvailable = true) {
  const input = page.getByRole('searchbox', {name: 'Search account settings'});
  await input.waitFor();
  assert.equal(await page.locator('.setting-row').first().evaluate(node => getComputedStyle(node).paddingInlineStart), '16px');
  await page.keyboard.press(process.platform === 'darwin' ? 'Meta+k' : 'Control+k');
  assert.equal(await input.evaluate(node => node === document.activeElement), true);
  assert.equal(await input.evaluate(node => getComputedStyle(node).outlineStyle), 'none', 'search input stays borderless inside Input Group');
  assert.notEqual(await page.locator('.settings-search .input-group').evaluate(node => getComputedStyle(node).boxShadow), 'none', 'Input Group owns its outer focus ring');
  assert.equal(await page.locator('[data-shortcut] > kbd').count(), 2, 'documented grouped key hints');
  await input.fill('password');
  assert.equal(await page.locator('#settings-results button').count(), passwordAvailable ? 1 : 0);
  await input.fill('nothing-matches');
  assert.equal(await page.locator('#settings-results').textContent(), 'No matching settings.');
  await page.keyboard.press('Escape');
  assert.equal(await input.inputValue(), '');
  assert.equal(await page.locator('#settings-results').isHidden(), true);
  await input.fill('profile');
  await captureScreen(page, 'settings-search-results');
  await page.keyboard.press('Tab');
  await page.keyboard.press('Enter');
  assert.equal(await page.locator('#heading').textContent(), 'Profile');
  assert.equal(await page.locator('#heading').evaluate(node => node === document.activeElement), true);
  await page.locator('#account-back').click();
  await input.fill('sessions');
  await page.getByRole('button', {name: 'Sessions', exact: true}).click();
  assert.equal(await page.locator('#heading').textContent(), 'Sessions');
  await page.waitForFunction(() => !document.querySelector('[aria-busy="true"]'));
  await page.locator('#account-back').click();
}
module.exports = {sharedLayout, settingsSearch};
