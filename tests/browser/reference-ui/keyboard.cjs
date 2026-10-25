'use strict';
const assert = require('node:assert/strict');

async function tabTo(page, selector) {
  for (let step = 0; step < 25; step += 1) {
    await page.keyboard.press('Tab');
    if (await page.locator(selector).evaluate(node => node === document.activeElement)) return;
  }
  assert.fail('account control must be reachable by keyboard');
}

async function cancelSignout(page) {
  let revocations = 0;
  const observe = request => {
    if (new URL(request.url()).pathname === '/v1/sessions/revoke-all') revocations += 1;
  };
  page.on('request', observe);
  try {
    await tabTo(page, '#revoke-all');
    await page.keyboard.press('Enter');
    await page.getByRole('dialog').waitFor({state: 'visible'});
    assert.equal(await page.getByRole('button', {name: 'Cancel', exact: true})
      .evaluate(node => node === document.activeElement), true);
    if (process.env.EASY_AUTH_UI_SCREENSHOT_DIR) await page.screenshot({animations: 'disabled', path: require('node:path').join(process.env.EASY_AUTH_UI_SCREENSHOT_DIR, 'destructive-confirmation.png'), fullPage: true});
    await page.keyboard.press('Escape');
    await page.waitForFunction(() => !document.querySelector('[aria-busy="true"]') &&
      document.activeElement === document.getElementById('revoke-all'));

    await page.keyboard.press('Enter');
    await page.getByRole('dialog').waitFor({state: 'visible'});
    // Explicit presentation-only negative control: another close listener chooses
    // a visible focus destination. Operation cleanup must preserve that choice.
    await page.evaluate(() => document.getElementById('confirmation').addEventListener('close',
      () => document.getElementById('heading').focus(), {once: true}));
    await page.keyboard.press('Escape');
    await page.waitForFunction(() => !document.querySelector('[aria-busy="true"]'));
    assert.equal(await page.locator('#heading').evaluate(node => node === document.activeElement), true);
    assert.equal(revocations, 0, 'keyboard cancellation sends no revocation request');
    assert.equal(await page.locator('#account').isVisible(), true);
  } finally { page.off('request', observe); }
}

async function accountKeyboard(page) {
  assert.equal(await page.locator('#heading').evaluate(node => node === document.activeElement), true,
    'genuine email completion focuses the account heading');
  await tabTo(page, '[data-open-account="details"]');
  await page.keyboard.press('Enter');
  assert.equal(await page.locator('#heading').textContent(), 'Profile');
  assert.equal(await page.locator('#heading').evaluate(node => node === document.activeElement), true);
  await page.keyboard.press('Shift+Tab');
  assert.equal(await page.locator('#settings-query').evaluate(node => node === document.activeElement), true,
    'search follows return navigation above the title');
  await page.keyboard.press('Shift+Tab');
  assert.equal(await page.locator('#account-back').evaluate(node => node === document.activeElement), true,
    'return navigation above the title remains reachable');
  await page.keyboard.press('Enter');
  assert.equal(await page.locator('#heading').textContent(), 'Account');

  await tabTo(page, '#manage-sessions');
  await page.keyboard.press('Enter');
  await page.waitForFunction(() => !document.querySelector('[aria-busy="true"]'));
  assert.equal(await page.locator('#heading').textContent(), 'Sessions');
  await cancelSignout(page);
  await tabTo(page, '#account-back');
  await page.keyboard.press('Enter');
  assert.equal(await page.locator('#heading').textContent(), 'Account');
  return {profile_and_return: true, sessions: true, dialog_cancel_restores_focus: true};
}

module.exports = {accountKeyboard};
