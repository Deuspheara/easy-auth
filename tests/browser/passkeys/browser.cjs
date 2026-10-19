'use strict';
const assert = require('node:assert/strict');

const START = '/v1/passkeys/enrollment/start';
const FINISH = '/v1/passkeys/enrollment/finish';

async function post(page, path, body) {
  return page.evaluate(async ({path, body}) => {
    const response = await fetch(path, {method: 'POST', headers: {'Content-Type': 'application/json'},
      body: JSON.stringify(body)});
    const text = await response.text();
    return {status: response.status, body: text ? JSON.parse(text) : null};
  }, {path, body});
}

async function start(page, options = {}) {
  const result = await post(page, START, {label: 'Browser test key', ...options});
  assert.equal(result.status, 200, 'start status');
  assert.equal(result.body.options.publicKey.authenticatorSelection.userVerification, 'required');
  assert.equal(result.body.options.publicKey.rp.id, 'localhost');
  return result.body;
}

async function create(page, options) {
  return page.evaluate(async options => {
    try {
      const publicKey = PublicKeyCredential.parseCreationOptionsFromJSON(options.publicKey);
      publicKey.timeout = 2000;
      const controller = new AbortController();
      const timer = setTimeout(() => controller.abort(), 5000);
      try {
        const credential = await navigator.credentials.create({publicKey, signal: controller.signal});
        return {credential: credential.toJSON()};
      } finally { clearTimeout(timer); }
    } catch (error) { return {error: error.name}; }
  }, options);
}

async function goodCredential(page, pending) {
  const result = await create(page, pending.options);
  assert.equal(Boolean(result.credential), true, 'native credential creation must succeed');
  return result.credential;
}

async function finish(page, pending, credential, expected = 201) {
  const response = await post(page, FINISH, {transaction_id: pending.transaction_id, credential});
  assert.equal(response.status, expected, 'finish status');
  return response;
}

async function withAuthenticator(browser, origin, session, transport, operation, options = {}) {
  const context = await browser.newContext();
  try {
    if (session !== undefined) {
      await context.addCookies([{name: 'auth-session', value: session, url: origin, httpOnly: true,
        sameSite: 'Lax', secure: false}]);
    }
    const page = await context.newPage();
    await page.goto(origin);
    const cdp = await context.newCDPSession(page);
    await cdp.send('WebAuthn.enable', {enableUI: false});
    const {authenticatorId} = await cdp.send('WebAuthn.addVirtualAuthenticator', {options: {
      protocol: 'ctap2', transport, hasResidentKey: true, hasUserVerification: true,
      isUserVerified: true, automaticPresenceSimulation: true, ...options
    }});
    return await operation({context, page, cdp, authenticatorId});
  } finally { await context.close(); }
}

function networkStatus(cdp, url) {
  // CORS-blocked responses may be absent from Playwright response events. Inspect
  // only CDP status codes, never request/response headers or credential payloads.
  const requests = new Set();
  const statuses = new Map();
  let resolveStatus, rejectStatus;
  const result = new Promise((resolve, reject) => { resolveStatus = resolve; rejectStatus = reject; });
  const check = id => { if (requests.has(id) && statuses.has(id)) resolveStatus(statuses.get(id)); };
  const requested = event => {
    if (event.request.url === url && event.request.method === 'POST') requests.add(event.requestId);
    check(event.requestId);
  };
  const responded = event => { statuses.set(event.requestId, event.statusCode); check(event.requestId); };
  cdp.on('Network.requestWillBeSent', requested);
  cdp.on('Network.responseReceivedExtraInfo', responded);
  const timer = setTimeout(() => rejectStatus(new Error('cross-origin network status unavailable')), 5000);
  return result.finally(() => {
    clearTimeout(timer);
    cdp.off('Network.requestWillBeSent', requested);
    cdp.off('Network.responseReceivedExtraInfo', responded);
  });
}

module.exports = {START, FINISH, post, start, create, goodCredential, finish, withAuthenticator, networkStatus};
