'use strict';
const assert = require('node:assert/strict');
const path = require('node:path');

async function screens(page, origin) {
  const views = [
    ['password', 'Sign in with password', '#password-form'],
    ['signup', 'Create your account', '#signup-form'],
    ['help', 'Let’s get you signed in', '#signin-help'],
    ['account-passkey', 'Use your account ID', '#account-passkey-form']
  ];
  for (const [view, heading, form] of views) {
    await page.goto(origin + '/?view=' + view);
    await page.waitForFunction(() => document.getElementById('clear-session').hidden === false);
    assert.equal(await page.locator('#heading').textContent(), heading);
    assert.equal(await page.locator(form).isVisible(), true);
    assert.equal(await page.locator('#email-form').isVisible(), false);
    assert.equal(await page.locator('#sign-in details').count(), 0, 'focused screens have no sign-in accordions');
    assert.equal(await page.locator('[data-auth-screen]:visible').count(), 1);
    for (const scheme of ['light', 'dark']) {
      await page.emulateMedia({colorScheme: scheme});
      for (const width of [320, 1440]) {
        await page.setViewportSize({width, height: 1000});
        await page.evaluate(() => document.fonts.ready);
        assert.equal(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth), true);
        if (process.env.EASY_AUTH_UI_SCREENSHOT_DIR) {
          await page.screenshot({path: path.join(process.env.EASY_AUTH_UI_SCREENSHOT_DIR,
            view + '-' + scheme + '-' + width + '.png'), fullPage: true});
        }
      }
      await page.setViewportSize({width: 320, height: 844});
      await page.evaluate(() => { document.documentElement.style.fontSize = '200%'; });
      assert.equal(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth), true, 'focused view text reflow');
      await page.evaluate(() => { document.documentElement.style.removeProperty('font-size'); });
    }
  }
  for (const query of ['view=inbox', 'view=unavailable', 'view=google&google=true']) {
    await page.goto(origin + '/?' + query);
    await page.waitForFunction(() => document.getElementById('clear-session').hidden === false);
    assert.equal(await page.locator('#email-form').isVisible(), true, 'unsupported presentation cannot select another method');
    assert.equal(await page.locator('#email-resend').isVisible(), false, 'inbox requires a real request in this page');
    assert.equal(await page.locator('[data-cap="google"]').isVisible(), false);
  }
  await page.getByRole('link', {name: 'Use a password instead', exact: true}).click();
  await page.locator('#password-form').waitFor({state: 'visible'});
  assert.equal(await page.locator('#password-form').isVisible(), true);
  await page.goBack();
  await page.waitForFunction(() => document.getElementById('clear-session').hidden === false);
  assert.equal(await page.locator('#email-form').isVisible(), true, 'browser back returns to the focused sign-in view');
  return {dedicated_views: views.length, both_themes_mobile_desktop: true,
    enlarged_text: true, query_grants_no_method: true, inbox_requires_request: true, browser_back: true};
}
module.exports = {screens};
