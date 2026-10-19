'use strict';
const assert = require('node:assert/strict');
const {profile} = require('../assertions.cjs');

// Controlled native rejections test feedback only; the scenario still finishes
// with the original production options and actual resident create/get signatures.
async function promptErrors(page) {
  let registrations = 0;
  const observed = request => {
    if (request.url().endsWith('/v1/passkeys/recovery/replacement/registration')) registrations += 1;
  };
  page.on('request', observed);
  try {
    for (const [name, prefix] of [
      ['NotAllowedError', 'Passkey creation was not completed.'],
      ['AbortError', 'Passkey creation was aborted by the browser or provider.']
    ]) {
      await page.evaluate(name => {
        const original = navigator.credentials.create.bind(navigator.credentials);
        navigator.credentials.create = async () => {
          navigator.credentials.create = original;
          throw new DOMException('private-provider-detail-must-not-be-echoed', name);
        };
      }, name);
      await page.locator('#replace-consent').check();
      await page.locator('#replace').click();
      await page.waitForFunction(prefix => document.getElementById('status').textContent.startsWith(prefix), prefix);
      assert.equal((await page.locator('#status').textContent()).includes('private-provider-detail'), false);
      await profile(page, 401);
    }
    await page.evaluate(() => {
      const original = navigator.credentials.create.bind(navigator.credentials);
      navigator.credentials.create = ({signal}) => {
        navigator.credentials.create = original;
        window.promptStartedForTest = true;
        return new Promise((_, reject) => signal.addEventListener('abort', () => {
          reject(new DOMException('private-provider-detail-must-not-be-echoed', 'AbortError'));
        }, {once: true}));
      };
    });
    await page.locator('#replace').click();
    await page.waitForFunction(() => window.promptStartedForTest === true);
    // A restored page must retain its changed generation even when pageshow
    // runs before the pending native abort's promise continuation.
    await page.evaluate(() => {
      window.dispatchEvent(new PageTransitionEvent('pagehide', {persisted: true}));
      window.dispatchEvent(new PageTransitionEvent('pageshow', {persisted: true}));
      delete window.promptStartedForTest;
    });
    await page.waitForFunction(() => document.getElementById('status').textContent.startsWith('The page changed while the operation was in progress.'));
    await profile(page, 401);
    assert.equal(registrations, 0, 'neither failed native creation nor navigation can submit registration');
    await page.locator('#resume').click();
    await page.waitForFunction(() => document.getElementById('status').textContent.startsWith('Original request resumed'));
  } finally { page.off('request', observed); }
}
async function verificationError(page, options) {
  const message = await page.evaluate(async options => {
    const {assertKey, failure} = await import('/passkey-recovery/shared.js');
    const original = navigator.credentials.get.bind(navigator.credentials);
    navigator.credentials.get = async () => {
      throw new DOMException('private-provider-detail-must-not-be-echoed', 'NotAllowedError');
    };
    try {
      await assertKey(options);
      return 'unexpected success';
    } catch (error) { return failure(error); }
    finally { navigator.credentials.get = original; }
  }, options);
  assert.equal(message.startsWith('Passkey verification was not completed.'), true);
  assert.equal(message.includes('private-provider-detail'), false);
}
module.exports = {promptErrors, verificationError};
