'use strict';
const assert = require('node:assert/strict');
const {test} = require('node:test');
const {ownedFetch} = require('./fetch.cjs');

test('owned Fetch refuses insecure, external and noncanonical issuer selection', () => {
  for (const origin of ['http://fixture.invalid', 'https://example.com', 'https://fixture.invalid/']) {
    assert.throws(() => ownedFetch(origin, Buffer.alloc(0)), assert.AssertionError);
  }
});

test('owned Fetch rejects forbidden target and credential inputs before network I/O', async () => {
  const origin = 'https://fixture.invalid:1';
  const transport = ownedFetch(origin, Buffer.alloc(0));
  const cases = [
    ['https://other.invalid/oidc/jwks', {}],
    [origin + '/oidc/jwks?target=x', {}],
    [origin + '/unconfigured', {}],
    [origin + '/oidc/jwks', {method: 'POST'}],
    [origin + '/oidc/jwks', {headers: {Cookie: 'owned-private-marker'}}],
    [origin + '/oidc/jwks', {headers: {Authorization: 'owned-private-marker'}}],
    [origin + '/oidc/jwks', {headers: {'Proxy-Authorization': 'owned-private-marker'}}],
    [origin + '/oidc/jwks', {body: 'unexpected'}],
    [origin + '/oidc/token', {method: 'POST', body: new Uint8Array(1)}],
    [origin + '/oidc/token', {method: 'POST', body: 'x'.repeat(65537)}],
  ];
  for (const [url, options] of cases) await assert.rejects(transport.fetch(url, options), assert.AssertionError);
  assert.deepEqual(transport.facts, {token_posts: 0, jwks_gets: 0});
});

test('already aborted requests do not reach the owned connector', async () => {
  const transport = ownedFetch('https://fixture.invalid:1', Buffer.alloc(0));
  const controller = new AbortController();
  controller.abort();
  await assert.rejects(transport.fetch('https://fixture.invalid:1/oidc/jwks', {signal: controller.signal}), {name: 'AbortError'});
  assert.deepEqual(transport.facts, {token_posts: 0, jwks_gets: 0});
});
