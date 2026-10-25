'use strict';
const assert = require('node:assert/strict');

async function signIn(page, origin, email, mail) {
  await page.goto(origin);
  await page.locator('#email').fill(email);
  await page.locator('#submit').click();
  await page.waitForFunction(() => document.getElementById('status').textContent.startsWith('Check your email.'));
  await page.goto(await mail.link(email, origin, 'Your sign-in link', '/'));
  await page.waitForFunction(() => document.querySelectorAll('#sessions > li').length === 1);
}

async function accountReturn(browser, origin, mail, guard) {
  const context = await browser.newContext();
  try {
    await guard(context);
    const page = await context.newPage();
    await signIn(page, origin, mail.recipient(9), mail);
    await page.getByRole('button', {name: 'Account details', exact: true}).click();
    await page.getByRole('button', {name: 'Change email address', exact: true}).click();
    await page.locator('#new-email').fill(mail.recipient(11));
    const peer = await context.newPage();
    await peer.goto(origin);
    await peer.locator('#logout').click();
    await peer.waitForFunction(() => document.getElementById('status').textContent === 'Signed out in this browser.');
    await signIn(peer, origin, mail.recipient(10), mail);
    await page.bringToFront();
    // The pinned headless driver reports focus on both pages and does not
    // reliably emit a native return event. Trigger only that UI event here;
    // the switched cookie, owner response and protected data are all genuine.
    await page.evaluate(() => window.dispatchEvent(new Event('focus')));
    try {
      await page.waitForFunction(email => document.getElementById('identity-email').textContent === email, mail.recipient(10));
    } catch (error) {
      error.uiObservations = await page.evaluate(() => ({accountState: document.body.dataset.account,
        visibility: document.visibilityState, focused: document.hasFocus(),
        busy: Boolean(document.querySelector('[aria-busy="true"]')),
        accountShown: !document.getElementById('account').hidden}));
      throw error;
    }
    assert.equal(await page.locator('#new-email').inputValue(), '', 'account switch clears unsubmitted previous-owner fields');
    assert.equal(await page.locator('#email-change-form').isVisible(), false);
    assert.equal(await page.locator('[data-account-panel="overview"]').isVisible(), true);
    assert.equal(await page.locator('#refresh-account').isVisible(), false, 'manual retry is absent after a healthy read');
    assert.equal(await page.locator('#check-session').isVisible(), false, 'diagnostics are outside the overview');
    assert.equal(await page.locator('#sessions .badge').textContent(), 'Current');
    assert.equal(await page.locator('#sessions button').count(), 0, 'the current session has no duplicate revoke action');
    await page.waitForFunction(() => document.getElementById('providers-card').dataset.loaded === 'true');
    assert.equal(await page.locator('#providers-card').isVisible(), false, 'unsupported connect is not invented for an empty inventory');
    return {return_event_refresh: true, simulated_focus_trigger: true, real_other_tab_switch: true, clears_previous_owner_form: true,
      current_session_identified: true, no_duplicate_current_revocation: true, diagnostics_separate: true};
  } finally { await context.close(); }
}
module.exports = {accountReturn};
