'use strict';
const assert = require('node:assert/strict');
const https = require('node:https');
const crypto = require('node:crypto');

// Owned test transport only. Trust the private fixture certificate explicitly;
// no system trust changes, disabled TLS verification or external destinations.
function client(origin, certificate, redirect = 'https://client.example/callback') {
  const expected = new URL(origin);
  assert.equal(expected.hostname,'app.example');
  const verifier = crypto.randomBytes(32).toString('base64url');
  const nonce = crypto.randomBytes(32).toString('base64url');
  const state = crypto.randomBytes(32).toString('base64url');
  async function request(path, form, access) {
    assert.ok(path.startsWith('/') && !path.startsWith('//'));
    const body = form && new URLSearchParams(form).toString();
    return new Promise((resolve,reject) => {
      const headers = body ? {'Content-Type':'application/x-www-form-urlencoded','Content-Length':Buffer.byteLength(body)} : {};
      if (access) headers.Authorization = 'Bearer ' + access;
      const req = https.request(new URL(path,origin),{
        method:body?'POST':'GET',ca:certificate,headers,
        lookup(host,options,callback) {
          assert.equal(host,expected.hostname);
          if (options.all) callback(null,[{address:'127.0.0.1',family:4}]);
          else callback(null,'127.0.0.1',4);
        }
      },response => {
        const chunks=[];let size=0;
        response.on('data',chunk => {size+=chunk.length;if(size>65536)response.destroy(new Error('owned body bound'));else chunks.push(chunk);});
        response.on('error',reject);
        response.on('end',() => {try {resolve({status:response.statusCode,headers:response.headers,value:chunks.length ? JSON.parse(Buffer.concat(chunks)) : null});}catch {reject(new Error('owned response envelope'));}});
      });
      req.setTimeout(5000,() => req.destroy(new Error('owned client timeout')));
      req.on('error',reject);req.end(body);
    });
  }
  return {nonce,state,challenge:crypto.createHash('sha256').update(verifier).digest('base64url'),request,
    token(code,id,wrong=false) {return request('/oidc/token',{grant_type:'authorization_code',client_id:id,code,redirect_uri:redirect,code_verifier:wrong?crypto.randomBytes(32).toString('base64url'):verifier});},
    verify(token,jwks,id) {
      const parts=token.split('.');assert.equal(parts.length,3);
      const header=JSON.parse(Buffer.from(parts[0],'base64url'));
      assert.equal(header.alg,'RS256');assert.equal(header.typ,'JWT');
      const jwk=jwks.keys.find(key => key.kid===header.kid);assert.ok(jwk);
      const key=crypto.createPublicKey({key:jwk,format:'jwk'});
      assert.equal(crypto.verify('RSA-SHA256',Buffer.from(parts[0]+'.'+parts[1]),key,Buffer.from(parts[2],'base64url')),true);
      const claims=JSON.parse(Buffer.from(parts[1],'base64url'));
      assert.equal(claims.iss,origin);assert.equal(claims.aud,id);assert.equal(claims.nonce,nonce);
      assert.match(claims.sub,/^[0-9a-f-]{36}$/);
      const now=Math.floor(Date.now()/1000);
      assert.ok(claims.auth_time<=claims.iat && claims.iat<=now && now<claims.exp && claims.exp-claims.iat<=60);
    }
  };
}
module.exports={client};
