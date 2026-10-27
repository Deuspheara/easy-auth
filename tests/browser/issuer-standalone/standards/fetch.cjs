'use strict';
const assert = require('node:assert/strict');
const https = require('node:https');

const MAX_RESPONSE_BYTES = 64 * 1024;
const REQUEST_TIMEOUT_MS = 5000;
const ENDPOINTS = new Map([
  ['/.well-known/openid-configuration', 'GET'],
  ['/oidc/jwks', 'GET'],
  ['/oidc/token', 'POST'],
]);

function target(origin, input, options) {
  const url = new URL(input);
  assert.equal(url.origin, origin, 'owned issuer origin only');
  assert.equal(url.username + url.password + url.search + url.hash, '', 'closed endpoint');
  assert.equal(ENDPOINTS.get(url.pathname), options.method || 'GET', 'closed method/path');
  const headers = new Headers(options.headers);
  assert.equal(headers.has('cookie') || headers.has('authorization'), false, 'cookie-free public client');
  assert.equal(headers.has('proxy-authorization'), false, 'no proxy credentials');
  const body = options.body;
  assert.ok(body === undefined || typeof body === 'string' || body instanceof URLSearchParams, 'bounded form input');
  const encoded = body === undefined ? undefined : body.toString();
  assert.ok(encoded === undefined || Buffer.byteLength(encoded) <= MAX_RESPONSE_BYTES, 'owned request bound');
  assert.ok(options.method === 'POST' || encoded === undefined, 'GET has no body');
  return {url, headers, body: encoded};
}

function responseBody(response, url, resolve, reject) {
  if (response.statusCode >= 300 && response.statusCode < 400) {
    response.destroy(new Error('owned client refuses redirects'));
    reject(new Error('owned client refuses redirects'));
    return;
  }
  const chunks = [];
  let size = 0;
  response.on('data', chunk => {
    size += chunk.length;
    if (size > MAX_RESPONSE_BYTES) response.destroy(new Error('owned response bound'));
    else chunks.push(chunk);
  });
  response.on('error', reject);
  response.on('aborted', () => reject(new Error('owned response interrupted')));
  response.on('end', () => {
    try {
      const headers = new Headers();
      for (const [name, value] of Object.entries(response.headers)) {
        if (value !== undefined) for (const item of Array.isArray(value) ? value : [value]) headers.append(name, item);
      }
      assert.equal(headers.has('set-cookie'), false, 'protocol responses grant no local cookie');
      assert.ok(!headers.has('content-encoding') || headers.get('content-encoding') === 'identity');
      const body = [204, 205, 304].includes(response.statusCode) ? null : Buffer.concat(chunks);
      const result = new Response(body, {status: response.statusCode, headers});
      Object.defineProperty(result, 'url', {value: url});
      resolve(result);
    } catch (error) { reject(error); }
  });
}

// Fetch-shaped fixture transport for the third-party RP. It passes original
// response bytes to that library; it never parses tokens or verifies signatures.
function ownedFetch(origin, certificate) {
  const issuer = new URL(origin);
  assert.equal(issuer.protocol, 'https:');
  assert.ok(['fixture.invalid', 'app.example'].includes(issuer.hostname));
  assert.equal(issuer.origin, origin, 'exact owned origin');
  const facts = {token_posts: 0, jwks_gets: 0};
  async function fetch(input, options = {}) {
    const selected = target(origin, input, options);
    options.signal?.throwIfAborted();
    if (selected.url.pathname === '/oidc/token') facts.token_posts++;
    if (selected.url.pathname === '/oidc/jwks') facts.jwks_gets++;
    return new Promise((resolve, reject) => {
      const request = https.request(selected.url, {
        method: options.method || 'GET', ca: certificate,
        headers: Object.fromEntries(selected.headers),
        lookup(host, settings, callback) {
          assert.equal(host, issuer.hostname);
          if (settings.all) callback(null, [{address: '127.0.0.1', family: 4}]);
          else callback(null, '127.0.0.1', 4);
        },
      }, response => responseBody(response, selected.url.href, resolve, reject));
      const abort = () => request.destroy(new Error('owned request aborted'));
      options.signal?.addEventListener('abort', abort, {once: true});
      request.on('close', () => options.signal?.removeEventListener('abort', abort));
      request.setTimeout(REQUEST_TIMEOUT_MS, () => request.destroy(new Error('owned client timeout')));
      request.on('error', reject);
      request.end(selected.body);
    });
  }
  return {fetch, facts};
}
module.exports = {ownedFetch};
