'use strict';
const assert = require('node:assert/strict');

// Called only after an existing genuine provider completion, with its unchanged
// configured trust, native token verification and committed owner observations.
async function providerAccount(page, origin, issuer, kind, deletion = true) {
  await page.goto(origin);
  await page.locator('#account').waitFor({state: 'visible'});
  await page.waitForFunction(() => document.querySelectorAll('#providers > li').length === 1);
  await page.waitForFunction(() => document.querySelectorAll('#sessions > li').length === 1);
  assert.equal(await page.locator('#providers > li p').last().textContent(), issuer);
  assert.equal(await page.locator('#providers a').count(), 0, 'issuer metadata never becomes navigation');
  assert.equal(await page.locator('#providers > li p').first().textContent(), kind === 'saml' ? 'SAML provider' : 'OpenID Connect provider');
  assert.equal(await page.locator('#mailbox-actions').isVisible(), false);
  assert.equal(await page.locator('#password-enrollment').isVisible(), false);
  assert.equal(await page.locator('#attach-action').isVisible(), false);
  assert.equal(await page.locator('#passkeys-card').isVisible(), false);
  assert.equal(await page.locator('#provider-deletion').isVisible(), deletion);
  assert.equal(await page.evaluate(() => localStorage.length + sessionStorage.length), 0);
}
module.exports = {providerAccount};
