'use strict';
const assert = require('node:assert/strict');

// Called after two genuine accepted requests for this owned recipient. The real
// PostgreSQL policy admits five per ten-minute window; no fake response or retry.
async function emailLimits(page) {
  for (let attempt = 3; attempt <= 6; attempt += 1) {
    const response = page.waitForResponse(value => new URL(value.url()).pathname === '/v1/email/start');
    await page.locator('#email-resend').click();
    assert.equal((await response).status(), attempt <= 5 ? 202 : 429);
    await page.waitForFunction(() => !document.querySelector('[aria-busy="true"]'));
    assert.equal(await page.locator('#email-resend').isEnabled(), true);
  }
  assert.equal(await page.locator('#status').textContent(), 'Too many attempts. Wait before trying again.');
  assert.equal(await page.locator('#status').getAttribute('data-variant'), 'destructive');
  assert.equal(await page.locator('#account').isVisible(), false, 'acceptance does not prove a session');
}
module.exports = {emailLimits};
