'use strict';
const assert = require('node:assert/strict');
const crypto = require('node:crypto');

async function openDetails(page, selector) {
  if (!await page.locator(selector).evaluate(node => node.open)) await page.locator(selector + ' > summary').click();
}
async function signedIn(page) {
  await page.locator('#account').waitFor({state: 'visible'});
  await page.waitForFunction(() => document.querySelectorAll('#sessions > li').length > 0);
}
async function passwordLogin(page, origin, email, password) {
  await page.goto(origin);
  await page.waitForFunction(() => document.getElementById('clear-session').hidden === false);
  await page.getByRole('link', {name: 'Use a password instead', exact: true}).click();
  await page.locator('#login-email').fill(email);
  await page.locator('#login-password').fill(password);
  await page.getByRole('button', {name: 'Sign in with password', exact: true}).click();
  await signedIn(page);
  assert.equal(await page.locator('#login-password').inputValue(), '');
}
async function emailLogin(page, origin, email, mail) {
  await page.goto(origin);
  await page.waitForFunction(() => document.getElementById('clear-session').hidden === false);
  await page.locator('#email').fill(email);
  await page.locator('#submit').click();
  await page.waitForFunction(() => document.getElementById('status').textContent.startsWith('Check your email.'));
  await page.goto(await mail.link(email, origin, 'Your sign-in link', '/'));
  await signedIn(page);
}
async function signoutAll(page) {
  await page.locator('#revoke-all').click();
  await page.getByRole('dialog').waitFor({state: 'visible'});
  assert.equal(await page.getByRole('button', {name: 'Cancel', exact: true}).evaluate(node => node === document.activeElement), true);
  await page.keyboard.press('Escape');
  await page.getByRole('dialog').waitFor({state: 'hidden'});
  await page.waitForFunction(() => document.getElementById('status').textContent.startsWith('Cancelled.'));
  assert.equal(await page.locator('#account').isVisible(), true);
  await page.locator('#revoke-all').click();
  await page.locator('#confirmation-accept').click();
  await page.waitForFunction(() => document.getElementById('clear-session').hidden === false);
  await page.waitForFunction(() => document.getElementById('status').textContent.startsWith('All sessions were signed out.'));
}

async function mailboxFlow(browser, origin, mail, guard) {
  const context = await browser.newContext();
  const peer = await browser.newContext();
  let stage = 'email-signin';
  const confirmations = [];
  let changeAddress = 0;
  try {
    await guard(context); await guard(peer);
    const page = await context.newPage();
    page.on('response', response => {
      if (new URL(response.url()).pathname === '/v1/account/email/confirm') confirmations.push(response.status());
    });
    const other = await peer.newPage();
    const email = mail.recipient(1), changedEmail = mail.recipient(2);
    const password = 'Reference first ' + crypto.randomUUID();
    const replacement = 'Reference replacement ' + crypto.randomUUID();
    await page.goto(origin);
    await page.locator('#email').fill(email);
    await page.locator('#submit').click();
    await page.waitForFunction(() => document.getElementById('status').textContent.startsWith('Check your email.'));
    assert.equal(await page.locator('#email-form').isVisible(), false);
    assert.equal(await page.locator('#heading').textContent(), 'Check your email');
    if (process.env.EASY_AUTH_UI_SCREENSHOT_DIR) {
      const path = require('node:path');
      await page.evaluate(() => document.fonts.ready);
      for (const scheme of ['light', 'dark']) {
        await page.emulateMedia({colorScheme: scheme});
        for (const width of [320, 1440]) {
          await page.setViewportSize({width, height: 1000});
          await page.screenshot({path: path.join(process.env.EASY_AUTH_UI_SCREENSHOT_DIR,
            'inbox-' + scheme + '-' + width + '.png'), fullPage: true});
        }
      }
    }
    const link = await mail.link(email, origin, 'Your sign-in link', '/');
    await page.goto(link);
    await signedIn(page);
    assert.equal(new URL(page.url()).hash, '');
    assert.equal(await page.locator('#providers-state').textContent(), 'No connected providers.');
    assert.equal(await page.locator('#mailbox-actions').isVisible(), true);

    stage = 'password-enrollment';
    await openDetails(page, '#password-enrollment');
    await page.locator('#new-password').fill(password);
    await page.locator('#confirm-password').fill(password);
    await page.getByRole('button', {name: 'Set up password', exact: true}).click();
    await page.waitForFunction(() => document.getElementById('status').textContent.startsWith('Password saved.'));
    assert.equal(await page.locator('#new-password').inputValue(), '');
    assert.equal(await page.locator('#confirm-password').inputValue(), '');

    stage = 'session-revocation';
    await passwordLogin(other, origin, email, password);
    await page.locator('#refresh-account').click();
    await page.waitForFunction(() => document.querySelectorAll('#sessions > li').length === 2);
    await page.locator('#sessions').getByRole('button', {name: 'Sign out session', exact: true}).click();
    await page.waitForFunction(() => document.querySelectorAll('#sessions > li').length === 1);
    await other.locator('#check-session').click();
    await other.waitForFunction(() => document.getElementById('clear-session').hidden === false);
    await other.getByRole('link', {name: 'Trouble signing in?', exact: true}).click();
    await other.locator('#clear-session').click();
    await other.waitForFunction(() => document.getElementById('status').textContent === 'Signed out in this browser.');
    await passwordLogin(other, origin, email, password);
    await signoutAll(page);
    await other.locator('#check-session').click();
    await other.waitForFunction(() => document.getElementById('clear-session').hidden === false);

    stage = 'password-reset';
    await page.getByRole('link', {name: 'Use a password instead', exact: true}).click();
    await page.locator('#login-email').fill(email);
    await page.locator('#reset-request').click();
    await page.waitForFunction(() => document.getElementById('status').textContent.startsWith('If this mailbox has a password'));
    await page.goto(await mail.link(email, origin, 'Password reset request', '/reset'));
    await page.locator('#password').fill(replacement);
    await page.locator('#confirm').fill(replacement);
    await page.locator('#save').click();
    await page.waitForFunction(() => document.getElementById('status').textContent.startsWith('Password reset.'));
    assert.equal(await page.locator('#password').inputValue(), '');
    await passwordLogin(page, origin, email, replacement);

    stage = 'email-change';
    await page.locator('#logout').click();
    await page.waitForFunction(() => document.getElementById('status').textContent === 'Signed out in this browser.');
    // Account lifecycle is an independent genuine account, keeping the preceding
    // password/session scenario within unchanged per-mailbox admission limits.
    const lifecycleEmail = mail.recipient(4);
    await emailLogin(page, origin, lifecycleEmail, mail);
    await openDetails(page, '#mailbox-actions details:first-child');
    await page.locator('#new-email').fill(changedEmail);
    await page.getByRole('button', {name: 'Send both confirmation links', exact: true}).click();
    await page.waitForFunction(() => document.getElementById('status').textContent.startsWith('Check both email inboxes.'));
    for (const address of [lifecycleEmail, changedEmail]) {
      changeAddress += 1;
      await page.goto(await mail.link(address, origin, 'Confirm email change', '/email-change'));
      await page.locator('#confirm').click();
      await page.waitForFunction(() => /This address is confirmed|Email changed\./.test(document.getElementById('status').textContent));
    }
    await emailLogin(page, origin, changedEmail, mail);

    stage = 'account-deletion';
    await openDetails(page, '#mailbox-actions details:last-child');
    await page.locator('#delete-confirmation').fill('delete my account');
    await page.getByRole('button', {name: 'Request deletion confirmation', exact: true}).click();
    await page.waitForFunction(() => document.getElementById('status').textContent.startsWith('Deletion was requested.'));
    await page.goto(await mail.link(changedEmail, origin, 'Confirm account deletion', '/account-delete'));
    await page.locator('#confirmation').fill('delete my account');
    await page.locator('#confirm').click();
    await page.waitForFunction(() => document.getElementById('status').textContent === 'Authentication account deleted.');
    assert.equal(await page.evaluate(() => localStorage.length + sessionStorage.length), 0);
    return {email_signin: true, password_enrollment_login_reset: true, session_revocation: true, email_change: true, deletion: true};
  } catch (error) { error.stageName = stage; error.uiObservations = {changeAddress, confirmations}; throw error; }
  finally { await context.close(); await peer.close(); }
}
module.exports = {mailboxFlow};
