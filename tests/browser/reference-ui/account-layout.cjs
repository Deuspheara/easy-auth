'use strict';
const assert = require('node:assert/strict');

async function accountLayout(page, email) {
  await page.setViewportSize({width: 1440, height: 1000});
  assert.equal(await page.locator('main').evaluate(node => node.getBoundingClientRect().width), 660);
  assert.equal(await page.locator('.brand').count(), 1);
  assert.equal(await page.locator('.topbar .brand').isVisible(), true);
  assert.equal(await page.locator('#avatar').textContent(), 'AM');
  assert.equal(await page.locator('#signin-methods > h2').textContent(), 'Security');
  assert.equal(await page.locator('#revoke-all').isVisible(), false, 'bulk sign-out belongs in management');
  assert.equal(await page.locator('.current-session #logout').isVisible(), true);
  assert.equal(await page.locator('#passkeys-summary').textContent(), 'View and manage registered passkeys',
    'returning to the account does not invent or retain sensitive inventory');
  await page.setViewportSize({width: 320, height: 844});
  const compact = await page.locator('#identity-email').evaluate(node => ({
    full: node.textContent, clipped: node.scrollWidth > node.clientWidth,
    overflow: getComputedStyle(node).textOverflow
  }));
  assert.equal(compact.full, email);
  assert.equal(compact.clipped, true);
  assert.equal(compact.overflow, 'ellipsis');
  await page.getByRole('button', {name: 'Account details', exact: true}).click();
  assert.equal(await page.locator('#details-email').textContent(), email);
  assert.equal(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth), true);
  await page.getByRole('button', {name: '← Account', exact: true}).click();
  await page.locator('#manage-sessions').click();
  await page.waitForFunction(() => document.querySelectorAll('#sessions > li').length === 1 &&
    !document.querySelector('[aria-busy="true"]'));
  assert.equal(await page.locator('#revoke-all').isVisible(), true);
  assert.equal(await page.locator('#status').textContent(), '', 'completed session reads clear pending feedback');
  assert.equal(await page.locator('#sessions .badge').textContent(), 'Current');
  assert.equal(await page.locator('#sessions button').count(), 0);
  if (process.env.EASY_AUTH_UI_SCREENSHOT_DIR) {
    const path = require('node:path');
    for (const scheme of ['light', 'dark']) {
      await page.emulateMedia({colorScheme: scheme});
      for (const width of [320, 1440]) {
        await page.setViewportSize({width, height: 1000});
        await page.screenshot({path: path.join(process.env.EASY_AUTH_UI_SCREENSHOT_DIR,
          'sessions-' + scheme + '-' + width + '.png'), fullPage: true});
      }
    }
  }
}
module.exports = {accountLayout};
