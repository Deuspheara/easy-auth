'use strict';
const assert = require('node:assert/strict');

async function passkeyInvalidation(page) {
  await page.waitForFunction(() => !document.querySelector('[aria-busy="true"]'));
  assert.equal(await page.locator('#passkeys > li').count(), 1);
  await page.locator('#account-back').click();
  let intercepted;
  const pending = new Promise(resolve => { intercepted = resolve; });
  const interrupt = route => { intercepted(route); };
  await page.route('**/v1/passkeys', interrupt);
  let route;
  try {
    await page.locator('#refresh-passkeys').click();
    route = await pending;
    assert.equal(await page.locator('#passkeys > li').count(), 0, 'new inventory reads clear previous key labels and actions');
    assert.equal(await page.locator('#passkeys-summary').textContent(), 'View and manage registered passkeys');
    assert.equal(await page.locator('#passkeys-state').textContent(), 'Checking passkey access…');
    await route.abort();
    route = null;
    await page.waitForFunction(() => !document.querySelector('[aria-busy="true"]'));
    assert.equal(await page.locator('#retry-passkeys').isVisible(), true);
    assert.equal(await page.locator('#passkeys > li').count(), 0, 'failed inventory never restores stale keys');
    assert.equal(await page.locator('#passkeys-summary').textContent(), 'View and manage registered passkeys');
    assert.equal(await page.locator('#passkeys-state').textContent(), 'The action was not confirmed. Refresh your account before trying again. Do not repeat a passkey or provider completion automatically.');
  } finally {
    if (route) await route.abort();
    await page.unroute('**/v1/passkeys', interrupt);
  }
  await page.locator('#retry-passkeys').click();
  await page.waitForFunction(() => !document.querySelector('[aria-busy="true"]') && document.querySelectorAll('#passkeys > li').length === 1);
  assert.equal(await page.locator('#passkeys-summary').textContent(), '1 registered passkey', 'explicit retry reloads genuine authorized inventory');
}
module.exports = {passkeyInvalidation};
