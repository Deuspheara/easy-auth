'use strict';
const assert = require('node:assert/strict');
const http = require('node:http');
const {complete} = require('./assertions.cjs');

async function frameAssertion(page, origin, pending) {
  const frameUrl = origin + '/assertion-context-fixture';
  // Only this controlled test document replaces framing headers, isolating core
  // signed-context policy. The actual API and its response headers are unchanged.
  await page.route(frameUrl, route => route.fulfill({contentType: 'text/html', body: `<!doctype html>
    <button id="sign">Sign</button><script>
    document.querySelector('#sign').onclick = async () => {
      try {
        const publicKey = PublicKeyCredential.parseRequestOptionsFromJSON(${JSON.stringify(pending.options.publicKey)});
        const credential = await navigator.credentials.get({publicKey});
        window.nativeAssertion = credential.toJSON();
      } catch (error) { window.nativeError = error.name; }
    };</script>`}));
  const parent = http.createServer((_, response) => {
    response.setHeader('Content-Type', 'text/html');
    response.setHeader('Permissions-Policy', `publickey-credentials-get=(self "${origin}")`);
    response.end(`<!doctype html><iframe src="${frameUrl}" allow="publickey-credentials-get *"></iframe>`);
  });
  await new Promise(resolve => parent.listen(0, '127.0.0.1', resolve));
  try {
    await page.goto(`http://localhost:${parent.address().port}`);
    await page.frameLocator('iframe').locator('#sign').click();
    const frame = page.frames().find(candidate => candidate.url() === frameUrl);
    assert.equal(Boolean(frame), true);
    await frame.waitForFunction(() => window.nativeAssertion || window.nativeError, null, {timeout: 10000});
    const result = await frame.evaluate(() => ({credential: window.nativeAssertion, error: window.nativeError}));
    assert.equal(Boolean(result.credential), true, 'native iframe produces an actual signed assertion');
    const clientData = JSON.parse(Buffer.from(result.credential.response.clientDataJSON, 'base64url').toString());
    assert.equal(clientData.crossOrigin, true, 'browser signs the cross-origin context');
    await complete(frame, pending, result.credential, 401);
  } finally {
    await new Promise(resolve => parent.close(resolve));
    await page.unroute(frameUrl);
    await page.goto(origin);
  }
}

module.exports = {frameAssertion};
