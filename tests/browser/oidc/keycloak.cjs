'use strict';
const assert = require('node:assert/strict');
const {execFileSync} = require('node:child_process');
const crypto = require('node:crypto');
const fs = require('node:fs');
const path = require('node:path');
const IMAGE = 'quay.io/keycloak/keycloak:26.8.1@sha256:79c623a22abacf3fe6c00a5fb30f5b7843d717b234033b80995891c06116d244';
const random = () => crypto.randomBytes(32).toString('base64url');
const pause = ms => new Promise(resolve => setTimeout(resolve, ms));
function docker(args, timeout = 30000) {
  return execFileSync('docker', args, {encoding: 'utf8', timeout, stdio: ['ignore','pipe','pipe']}).trim();
}
async function json(url, options = {}) {
  const response = await fetch(url, {...options, redirect: 'error', signal: AbortSignal.timeout(5000)});
  return {response, value: response.status === 204 || response.status === 201 ? null : await response.json()};
}

async function start(directory, origin, redirect) {
  const owner = crypto.randomUUID();
  const name = 'easy-auth29-' + owner;
  const adminUser = 'bootstrap-' + owner;
  const adminPassword = random();
  const envFile = path.join(directory, 'keycloak.env');
  fs.writeFileSync(envFile, `KC_BOOTSTRAP_ADMIN_USERNAME=${adminUser}\nKC_BOOTSTRAP_ADMIN_PASSWORD=${adminPassword}\nKC_HOSTNAME=${origin}\nKC_PROXY_HEADERS=xforwarded\n`, {mode: 0o600});
  let removed = false;
  const stop = () => {
    if (removed) return;
    // The random name and owner label were chosen by this invocation before run,
    // so a timed-out start can be cleaned without looking up unrelated containers.
    const label = docker(['inspect','--format','{{index .Config.Labels "easy-auth.owner"}}',name]);
    assert.equal(label, owner, 'only the exact owned provider can be removed');
    docker(['rm','--force',name]);
    removed = true;
  };
  try {
    docker(['run','--detach','--name',name,'--label','easy-auth.owner='+owner,
      '-p','127.0.0.1::8080','--env-file',envFile,IMAGE,'start-dev'], 180000);
    const binding = docker(['port',name,'8080/tcp']);
    assert.equal(binding.startsWith('127.0.0.1:'), true);
    const base = 'http://' + binding;
    const deadline = Date.now() + 100000;
    while (true) {
      try {
        const {response} = await json(base + '/realms/master/.well-known/openid-configuration');
        if (response.status === 200) break;
      } catch { /* owned process readiness only, no captured diagnostics */ }
      assert.equal(Date.now() < deadline, true, 'owned Keycloak readiness deadline');
      await pause(500);
    }
    const auth = await json(base + '/realms/master/protocol/openid-connect/token', {
      method: 'POST', body: new URLSearchParams({grant_type:'password',client_id:'admin-cli',username:adminUser,password:adminPassword})});
    assert.equal(auth.response.status, 200, 'owned admin provisioning control');
    const headers = {Authorization:'Bearer '+auth.value.access_token,'Content-Type':'application/json'};
    const realm = 'owned-' + owner;
    const client = 'client-' + owner;
    const secret = random();
    const username = 'user-' + owner;
    const password = random();
    const admin = async (suffix, method = 'GET', body) => {
      const result = await json(base + '/admin/realms/' + realm + suffix, {
        method, headers, ...(body === undefined ? {} : {body:JSON.stringify(body)})});
      assert.equal(result.response.ok, true, 'owned provider administrative request');
      return result.value;
    };
    const created = await json(base + '/admin/realms', {method:'POST',headers,
      body:JSON.stringify({realm,enabled:true,sslRequired:'none',registrationAllowed:false,
        clients:[{clientId:client,enabled:true,protocol:'openid-connect',publicClient:false,secret,
          clientAuthenticatorType:'client-secret',standardFlowEnabled:true,implicitFlowEnabled:false,
          directAccessGrantsEnabled:false,defaultClientScopes:['profile'],optionalClientScopes:[],redirectUris:[redirect],attributes:{'pkce.code.challenge.method':'S256'}}],
        users:[{username,enabled:true,email:username+'@localhost.test',emailVerified:false,firstName:'Owned',lastName:'Fixture',
          credentials:[{type:'password',value:password,temporary:false}]}]})});
    assert.equal(created.response.status, 201);
    const realmInfo = await admin('');
    const clients = await admin('/clients?clientId='+encodeURIComponent(client));
    const users = await admin('/users?username='+encodeURIComponent(username)+'&exact=true');
    assert.equal(clients.length, 1);assert.equal(users.length, 1);
    const clientId = clients[0].id;
    let mapper;
    return {image:IMAGE, base, issuer:origin+'/realms/'+realm, client, secret, username, password,
      subject:users[0].id, realm, stop,
      async rotate() {
        const keysBefore = await admin('/keys');
        await admin('/components','POST',{name:'owned-rotation',parentId:realmInfo.id,
          providerId:'rsa-generated',providerType:'org.keycloak.keys.KeyProvider',
          config:{priority:['200'],enabled:['true'],active:['true'],algorithm:['RS256'],keySize:['2048']}});
        const keysAfter = await admin('/keys');
        assert.equal(typeof keysAfter.active.RS256, 'string');
        assert.equal(keysBefore.active.RS256 !== keysAfter.active.RS256, true, 'real provider signing-key rotation');
        return keysAfter.active.RS256;
      },
      async audience(enabled) {
        if (enabled) {
          const name = 'owned-untrusted-audience';
          await admin('/clients/'+clientId+'/protocol-mappers/models','POST',{name,protocol:'openid-connect',
            protocolMapper:'oidc-audience-mapper',consentRequired:false,
            config:{'included.custom.audience':'untrusted-fixture-audience','id.token.claim':'true','access.token.claim':'false'}});
          const mappers = await admin('/clients/'+clientId+'/protocol-mappers/models');
          mapper = mappers.find(value => value.name === name)?.id;
          assert.equal(typeof mapper, 'string');
        } else {
          await admin('/clients/'+clientId+'/protocol-mappers/models/'+mapper,'DELETE');
        }
      }
    };
  } catch (error) {
    try { stop(); } catch { error.cleanupFailed = true; }
    throw error;
  } finally { fs.rmSync(envFile, {force:true}); }
}
module.exports = {start, pause};
