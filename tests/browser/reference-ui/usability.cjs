'use strict';
const assert = require('node:assert/strict');

async function usability(browser, origin, mail, guard) {
  const context = await browser.newContext();
  let release;
  try {
    await guard(context);
    const page = await context.newPage();
    await page.goto(origin);
    await page.locator('#clear-session').waitFor({state: 'visible'});
    for (const method of ['oidc', 'google', 'saml']) {
      assert.equal(await page.locator('[data-cap="' + method + '"]').isVisible(), false);
    }
    assert.equal(await page.locator('#email').getAttribute('autocomplete'), 'email');
    assert.equal(await page.locator('#login-password').getAttribute('autocomplete'), 'current-password');
    assert.equal(await page.locator('#new-password').getAttribute('autocomplete'), 'new-password');

    // Hold transport only; eventually forward the unchanged request to the real
    // service. This observes busy presentation without a fabricated success.
    const gate = new Promise(resolve => { release = resolve; });
    await page.route('**/v1/email/start', async route => { await gate; await route.continue(); });
    await page.locator('#email').fill(mail.recipient(5));
    await page.locator('#submit').click();
    await page.waitForFunction(() => document.getElementById('email-form').getAttribute('aria-busy') === 'true');
    assert.equal(await page.locator('#submit').isDisabled(), true);
    release();
    await page.waitForFunction(() => document.getElementById('status').textContent.startsWith('Check your email.'));
    assert.equal(await page.locator('#submit').isEnabled(), true);
    await page.unroute('**/v1/email/start');

    await page.locator('details[data-cap="passwords"] > summary').click();
    await page.locator('#login-email').fill(mail.recipient(6));
    await page.locator('#login-password').fill('Unsubmitted reference offline password');
    await context.setOffline(true);
    await page.getByRole('button', {name: 'Sign in with password', exact: true}).click();
    await page.waitForFunction(() => document.getElementById('status').textContent.startsWith('The action was not confirmed.'));
    assert.equal(await page.locator('#login-password').inputValue(), '');
    assert.equal(await page.locator('#password-form').getAttribute('aria-busy'), null);
    assert.equal(await page.locator('#account').isVisible(), false);
    await context.setOffline(false);
    await page.locator('#check-session').click();
    await page.waitForFunction(() => document.getElementById('status').textContent === 'This browser is signed out.');
    await page.locator('#theme').click();
    assert.equal(await page.locator('html').getAttribute('data-theme'), 'dark');
    await page.goto(origin);
    assert.equal(await page.locator('html').getAttribute('data-theme'), null);
    assert.equal(await page.evaluate(() => localStorage.length + sessionStorage.length), 0);
    const navigating = new Promise(resolve => { release = resolve; });
    await page.route('**/v1/email/start', async route => {
      await navigating;
      try { await route.continue(); } catch { /* The genuine navigation cancelled this owned request. */ }
    });
    await page.locator('#email').fill(mail.recipient(7));
    await page.locator('#submit').click();
    await page.waitForFunction(() => document.getElementById('email-form').getAttribute('aria-busy') === 'true');
    await page.goto(origin + '/reset');
    release();
    await page.goto(origin);
    await page.locator('#clear-session').waitFor({state: 'visible'});
    assert.equal(await page.locator('#email-form').getAttribute('aria-busy'), null);
    assert.equal(await page.locator('#status').textContent(), '');
    assert.equal(await page.locator('#account').isVisible(), false);
    return {selected_methods_only: true, autocomplete: true, genuine_request_busy: true,
      offline_error_clears_password: true, no_false_signin: true, ephemeral_theme: true, navigation_discards_old_result: true};
  } finally { release?.(); await context.close(); }
}
module.exports = {usability};
