'use strict';
const assert = require('node:assert/strict');
const http = require('node:http');
const {START, FINISH, post, start, create, goodCredential, finish, withAuthenticator, networkStatus} = require('./browser.cjs');

async function runCases(browser, origin, sessions) {
  const results = [];
  async function run(name, transport, operation) {
    console.log(JSON.stringify({case: name, status: 'running'}));
    let detail;
    try { detail = await withAuthenticator(browser, origin, sessions[results.length], transport, operation); }
    catch (error) { error.caseName = name; throw error; }
    results.push({name, transport, status: 'passed', ...(detail || {})});
    console.log(JSON.stringify({case: name, status: 'passed'}));
  }
  for (const transport of ['internal', 'usb']) {
    await run(`registration-${transport}-and-replay`, transport, async ({context, page}) => {
      const pending = await start(page);
      const credential = await goodCredential(page, pending);
      await finish(page, pending, credential);
      await finish(page, pending, credential, 401);
      const denied = await post(page, START, {label: 'Unproved additional enrollment'});
      assert.equal(denied.status, 401, 'recent mailbox session cannot add another key');
      const cookies = await context.cookies();
      const binding = cookies.find(cookie => cookie.name === 'auth-passkey');
      assert.equal(Boolean(binding), true, 'binding cookie set');
      assert.equal(binding.httpOnly, true, 'binding is HttpOnly');
      assert.equal(binding.sameSite, 'Lax');
      assert.equal(await page.evaluate(() => document.cookie.includes('auth-')), false,
        'authentication cookies are absent from JavaScript');
    });
  }
  for (const field of ['challenge', 'origin']) {
    await run(`tampered-client-${field}`, 'internal', async ({page}) => {
      const pending = await start(page);
      const good = await goodCredential(page, pending);
      const bad = structuredClone(good);
      const data = JSON.parse(Buffer.from(bad.response.clientDataJSON, 'base64url').toString());
      data[field] = field === 'origin' ? 'http://localhost:1' : 'unrelated-challenge';
      bad.response.clientDataJSON = Buffer.from(JSON.stringify(data)).toString('base64url');
      await finish(page, pending, bad, 401);
      await finish(page, pending, good);
    });
  }
  await run('browser-rejects-unrelated-rp', 'internal', async ({page}) => {
    const pending = await start(page);
    const bad = structuredClone(pending.options);
    bad.publicKey.rp.id = 'example.com';
    const result = await create(page, bad);
    assert.equal(result.error, 'SecurityError', 'browser enforces RP scope');
    await finish(page, pending, await goodCredential(page, pending));
  });
  await run('required-user-verification', 'internal', async ({page, cdp, authenticatorId}) => {
    const pending = await start(page);
    await cdp.send('WebAuthn.setResponseOverrideBits', {authenticatorId, isBadUV: true});
    const bad = await create(page, pending.options);
    let rejectedBy;
    if (bad.credential) {
      await finish(page, pending, bad.credential, 401);
      rejectedBy = 'server';
    } else {
      assert.equal(bad.error, 'NotAllowedError', 'browser must reject invalid UV, not hit the abort guard');
      rejectedBy = 'browser';
    }
    await cdp.send('WebAuthn.setResponseOverrideBits', {authenticatorId});
    await finish(page, pending, await goodCredential(page, pending));
    return {rejected_by: rejectedBy};
  });
  await run('real-cross-origin-post', 'internal', async ({page, cdp}) => {
    const attacker = http.createServer((_, response) => response.end('<!doctype html><title>Test origin</title>'));
    await new Promise(resolve => attacker.listen(0, '127.0.0.1', resolve));
    try {
      await page.goto(`http://localhost:${attacker.address().port}`);
      await cdp.send('Network.enable');
      const rejected = networkStatus(cdp, origin + START);
      await page.evaluate(async origin => {
        try { await fetch(origin + '/v1/passkeys/enrollment/start', {method: 'POST', credentials: 'include',
          headers: {'Content-Type': 'text/plain'}, body: '{"label":"untrusted origin"}'}); } catch {}
      }, origin);
      assert.equal(await rejected, 403, 'server rejects the actual browser Origin');
      await page.goto(origin);
      const pending = await start(page);
      await finish(page, pending, await goodCredential(page, pending));
    } finally { await new Promise(resolve => attacker.close(resolve)); }
  });
  await run('other-browser-binding-denied', 'usb', async ({page}) => {
    const pending = await start(page);
    const credential = await goodCredential(page, pending);
    const peer = await browser.newContext();
    try {
      await peer.addCookies([{name: 'auth-session', value: sessions[results.length], url: origin,
        httpOnly: true, sameSite: 'Lax', secure: false}]);
      const rejected = await peer.request.post(origin + FINISH, {headers: {Origin: origin},
        data: {transaction_id: pending.transaction_id, credential}});
      assert.equal(rejected.status(), 401, 'same session without browser binding is denied');
    } finally { await peer.close(); }
    await finish(page, pending, credential);
  });
  return results;
}

module.exports = {runCases};
