'use strict';
const assert = require('node:assert/strict');
const path = require('node:path');
const {createRequire} = require('node:module');
const {pathToFileURL} = require('node:url');
const {ownedFetch} = require('./fetch.cjs');

const browserTools = createRequire(path.resolve(__dirname, '../../passkeys/package.json'));
const REDIRECT = 'https://client.example/callback';
const INVALID_RESPONSE = 'OAUTH_INVALID_RESPONSE';

async function standardsClient(origin, certificate, clientId) {
  const api = await import(pathToFileURL(browserTools.resolve('openid-client')).href);
  const transport = ownedFetch(origin, certificate);
  const configuration = await api.discovery(new URL(origin), clientId,
    {redirect_uris: [REDIRECT], id_token_signed_response_alg: 'RS256'}, api.None(), {
      [api.customFetch]: transport.fetch, timeout: 5,
      // Code flow can rely on TLS alone by default. Require actual JWKS/JWS
      // verification too; no signature/claim/HTTPS check is disabled here.
      execute: [api.enableNonRepudiationChecks],
    });
  assert.equal(configuration.serverMetadata().issuer, origin);
  let subject;

  async function grant(consent, wrongState) {
    const verifier = api.randomPKCECodeVerifier();
    const nonce = api.randomNonce();
    const state = api.randomState();
    const authorization = api.buildAuthorizationUrl(configuration, {
      redirect_uri: REDIRECT, scope: 'openid', state, nonce,
      code_challenge: await api.calculatePKCECodeChallenge(verifier), code_challenge_method: 'S256',
    });
    const callback = new URL(await consent(authorization.href, 'approve'));
    assert.equal(callback.origin + callback.pathname, REDIRECT, 'exact owned callback');
    if (wrongState) callback.searchParams.set('state', api.randomState());
    const posts = transport.facts.token_posts;
    const complete = () => api.authorizationCodeGrant(configuration, callback, {
      pkceCodeVerifier: verifier, expectedState: state, expectedNonce: nonce, idTokenExpected: true,
    });
    if (wrongState) {
      await assert.rejects(complete, error => error?.code === INVALID_RESPONSE);
      assert.equal(transport.facts.token_posts, posts, 'wrong state must send no code');
      return;
    }
    const tokens = await complete();
    assert.equal(transport.facts.token_posts, posts + 1, 'one code attempt');
    const claims = tokens.claims();
    assert.ok(claims);
    assert.equal(claims.iss, origin);
    assert.equal(claims.aud, clientId);
    assert.equal(claims.nonce, nonce);
    assert.equal(typeof claims.sub, 'string');
    if (subject !== undefined) assert.equal(claims.sub, subject, 'stable same-client pairwise subject');
    subject = claims.sub;
    assert.ok(transport.facts.jwks_gets > 0, 'third-party signature validation fetched JWKS');
    assert.equal('refresh_token' in tokens, false, 'online grant creates no offline credential');
    // Tokens and callback values remain private in this scope, never report data.
  }
  return {
    verify: consent => grant(consent, false),
    rejectWrongState: consent => grant(consent, true),
  };
}
module.exports = {standardsClient};
