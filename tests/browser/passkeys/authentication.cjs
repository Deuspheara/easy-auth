'use strict';
const assert = require('node:assert/strict');
const {withAuthenticator} = require('./browser.cjs');
const {AUTH_FINISH, profile, enroll, startLogin, assertion, complete} = require('./assertions.cjs');
const {frameAssertion} = require('./frame-assertion.cjs');

function properties(cdp, authenticatorId, credentialId, values) {
  // CDP binary fields use standard base64; browser credential JSON uses base64url.
  return cdp.send('WebAuthn.setCredentialProperties', {authenticatorId,
    credentialId: Buffer.from(credentialId, 'base64url').toString('base64'), ...values});
}

async function runAuthenticationCases(browser, origin, sessions, prepareCounterless) {
  const results = [];
  async function run(name, transport, operation, options = {}) {
    console.log(JSON.stringify({case: name, status: 'running'}));
    let detail;
    try { detail = await withAuthenticator(browser, origin, sessions[results.length], transport, operation, options); }
    catch (error) { error.caseName = name; throw error; }
    results.push({name, transport, status: 'passed', authentications: 1, ...(detail || {})});
    console.log(JSON.stringify({case: name, status: 'passed'}));
  }
  for (const transport of ['internal', 'usb']) {
    await run(`assertion-account-bound-${transport}`, transport, async ({page}) => {
      const {owner} = await enroll(page);
      const pending = await startLogin(page, 'account_bound', owner);
      const credential = await assertion(page, pending);
      await complete(page, pending, credential);
      assert.equal((await profile(page)).id, owner, 'new session owns the verified account');
      await complete(page, pending, credential, 401);
    }, {hasResidentKey: false});
  }
  for (const transport of ['internal', 'usb']) {
    await run(`assertion-resident-modal-${transport}`, transport, async ({page}) => {
      const {owner} = await enroll(page, true);
      const pending = await startLogin(page, 'discoverable');
      const credential = await assertion(page, pending);
      assert.equal(Boolean(credential.response.userHandle), true, 'browser supplies the discovered handle');
      await complete(page, pending, credential);
      assert.equal((await profile(page)).id, owner);
    });
  }
  for (const [name, override] of [['uv', 'isBadUV'], ['up', 'isBadUP'], ['signature', 'isBogusSignature']]) {
    await run(`assertion-rejects-bad-${name}`, 'internal', async ({page, cdp, authenticatorId}) => {
      const {owner} = await enroll(page);
      const pending = await startLogin(page, 'account_bound', owner);
      await cdp.send('WebAuthn.setResponseOverrideBits', {authenticatorId, [override]: true});
      await complete(page, pending, await assertion(page, pending), 401);
      await profile(page, 401);
      await cdp.send('WebAuthn.setResponseOverrideBits', {authenticatorId});
      await complete(page, pending, await assertion(page, pending));
    });
  }
  await run('assertion-rejects-other-browser-binding', 'usb', async ({page}) => {
    const {owner} = await enroll(page);
    const pending = await startLogin(page, 'account_bound', owner);
    const credential = await assertion(page, pending);
    const peer = await browser.newContext();
    try {
      const response = await peer.request.post(origin + AUTH_FINISH, {headers: {Origin: origin},
        data: {transaction_id: pending.transaction_id, credential}});
      assert.equal(response.status(), 401);
    } finally { await peer.close(); }
    await complete(page, pending, credential);
  });
  await run('assertion-rejects-signed-cross-origin-frame', 'internal', async ({page}) => {
    const {owner} = await enroll(page);
    const pending = await startLogin(page, 'account_bound', owner);
    await frameAssertion(page, origin, pending);
    await complete(page, pending, await assertion(page, pending));
  });
  await run('assertion-rejects-backup-eligibility-upgrade', 'internal', async ({page, cdp, authenticatorId}) => {
    const {owner, credentialId} = await enroll(page);
    const pending = await startLogin(page, 'account_bound', owner);
    await properties(cdp, authenticatorId, credentialId, {backupEligibility: true});
    await complete(page, pending, await assertion(page, pending), 401);
    await properties(cdp, authenticatorId, credentialId, {backupEligibility: false});
    await complete(page, pending, await assertion(page, pending));
  });
  await run('assertion-updates-eligible-backup-state', 'internal', async ({page, cdp, authenticatorId}) => {
    const {owner, credentialId} = await enroll(page);
    const pending = await startLogin(page, 'account_bound', owner);
    await properties(cdp, authenticatorId, credentialId, {backupState: true});
    await complete(page, pending, await assertion(page, pending));
  }, {defaultBackupEligibility: true});
  await run('assertion-accepts-repeated-zero-counters-with-one-use-challenges', 'internal', async ({page, cdp, authenticatorId}) => {
    const {owner, credentialId} = await enroll(page);
    await properties(cdp, authenticatorId, credentialId, {signCount: -1});
    const nonzero = await startLogin(page, 'account_bound', owner);
    const reset = await assertion(page, nonzero);
    assert.equal(Buffer.from(reset.response.authenticatorData, 'base64url').readUInt32BE(33), 0);
    await complete(page, nonzero, reset, 401);
    await profile(page, 401);
    // Explicit trusted-storage setup models a credential enrolled counterless. It
    // changes no public key, signature verification or session-issuance implementation.
    await prepareCounterless();
    for (let index = 0; index < 2; index++) {
      const pending = await startLogin(page, 'account_bound', owner);
      const credential = await assertion(page, pending);
      const data = Buffer.from(credential.response.authenticatorData, 'base64url');
      assert.equal(data.readUInt32BE(33), 0, 'real signed zero counter');
      await complete(page, pending, credential);
      await complete(page, pending, credential, 401);
    }
    return {authentications: 2, counterless_storage_fixture: true, nonzero_to_zero_rejected: true};
  });
  return results;
}

module.exports = {runAuthenticationCases};
