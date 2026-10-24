'use strict';
const assert = require('node:assert/strict');
const http = require('node:http');
const https = require('node:https');
const crypto = require('node:crypto');
const fs = require('node:fs');
const path = require('node:path');
const {execFileSync} = require('node:child_process');

async function start(directory) {
  const key = path.join(directory, 'fixture.key');
  const certificate = path.join(directory, 'fixture.pem');
  execFileSync('openssl',['req','-x509','-newkey','rsa:2048','-nodes','-days','1',
    '-subj','/CN=fixture.invalid','-addext','subjectAltName=DNS:fixture.invalid,DNS:app.example',
    '-addext','basicConstraints=critical,CA:FALSE','-keyout',key,'-out',certificate],
    {stdio:['ignore','pipe','pipe'],timeout:15000});
  fs.chmodSync(key,0o600);
  const facts = {posts:0,token_responses:0,signature_mutations:0,token_replays:0};
  const faults = {unavailable:0};
  const clientAuthentication = {basic:0,post:0,public:0};
  let application,callbackCaptures=0;
  let base, origin, callback, mode = 'normal', captured, firstRequest, lastClaims, lastKid;
  const server = https.createServer({key:fs.readFileSync(key),cert:fs.readFileSync(certificate)}, (incoming, outgoing) => {
    // An explicitly selected bootstrap capture owns only its exact callback.
    // Clear it before exercising the application's real deletion callback/UI.
    if (callback && incoming.headers.host===new URL(callback).host && incoming.url.split('?')[0]===new URL(callback).pathname) {
      if(incoming.method!=='GET'){outgoing.writeHead(405);outgoing.end();return;}
      callbackCaptures++;
      outgoing.writeHead(200,{'Content-Type':'text/html','Cache-Control':'no-store','Referrer-Policy':'no-referrer',
        'Content-Security-Policy':"default-src 'none'"});
      outgoing.end('<!doctype html><title>Owned callback captured</title>');return;
    }
    if (application && incoming.headers.host===application.host) {
      const upstream=http.request(application.base+incoming.url,{method:incoming.method,headers:incoming.headers},response=>{
        outgoing.writeHead(response.statusCode,response.headers);response.pipe(outgoing);
      });
      upstream.on('error',()=>{outgoing.writeHead(502);outgoing.end();});
      incoming.pipe(upstream);return;
    }
    const token = incoming.method === 'POST' && incoming.url.endsWith('/protocol/openid-connect/token');
    const chunks = [];
    let bytes = 0;
    incoming.on('data', chunk => {bytes+=chunk.length;if(bytes>16384) incoming.destroy();else chunks.push(chunk);});
    incoming.on('end', () => {
      const body = Buffer.concat(chunks);
      if (token) {
        facts.posts += 1;
        if(typeof incoming.headers.authorization==='string' && /^Basic /i.test(incoming.headers.authorization))clientAuthentication.basic++;
        else if(new URLSearchParams(body.toString()).has('client_secret'))clientAuthentication.post++;
        else clientAuthentication.public++;

        firstRequest ||= {path:incoming.url,authorization:incoming.headers.authorization,body:Buffer.from(body)};
      }
      if(token && mode==='unavailable') {
        faults.unavailable++;
        outgoing.writeHead(503,{'Content-Type':'application/json'});outgoing.end('{"error":"temporarily_unavailable"}');return;
      }
      const headers = {...incoming.headers,host:new URL(origin).host,
        'x-forwarded-proto':'https','x-forwarded-host':'fixture.invalid',
        'x-forwarded-port':String(server.address().port)};
      const upstream = http.request(base + incoming.url, {method:incoming.method,headers}, response => {
        if (!token || response.statusCode !== 200) {
          outgoing.writeHead(response.statusCode,response.headers);response.pipe(outgoing);return;
        }
        const responseChunks = [];
        let size = 0;
        response.on('data', chunk => {size+=chunk.length;if(size>65536)response.destroy();else responseChunks.push(chunk);});
        response.on('end', () => {
          try {
            const value = JSON.parse(Buffer.concat(responseChunks));
            const parts = value.id_token.split('.');
            lastKid = JSON.parse(Buffer.from(parts[0],'base64url')).kid;
            lastClaims = JSON.parse(Buffer.from(parts[1],'base64url'));
            facts.token_responses += 1;
            captured ||= value.id_token;
            if (mode === 'bad-signature') {
              parts[2] = (parts[2][0] === 'A' ? 'B' : 'A') + parts[2].slice(1);
              value.id_token = parts.join('.');facts.signature_mutations += 1;
            }
            if (mode === 'replay-token') {value.id_token=captured;facts.token_replays += 1;}
            const encoded = Buffer.from(JSON.stringify(value));
            const returned = {...response.headers,'content-length':String(encoded.length)};
            delete returned['transfer-encoding'];
            outgoing.writeHead(response.statusCode,returned);outgoing.end(encoded);
          } catch {outgoing.writeHead(502);outgoing.end();}
        });
      });
      upstream.on('error', () => {outgoing.writeHead(502);outgoing.end();});
      upstream.end(body);
    });
  });
  await new Promise((resolve,reject) => {server.once('error',reject);server.listen(0,'127.0.0.1',resolve);});
  origin = 'https://fixture.invalid:'+server.address().port;
  return {origin,address:'127.0.0.1:'+server.address().port,
    certificate_der:Array.from(new crypto.X509Certificate(fs.readFileSync(certificate)).raw),facts,
    connectApplication(value, publicOrigin) {
      assert.match(value,/^http:\/\/127\.0\.0\.1:\d+$/);
      const url=new URL(publicOrigin);
      assert.equal(url.protocol,'https:');assert.equal(url.hostname,'app.example');
      assert.equal(url.port,String(server.address().port));
      application={base:value,host:url.host};
    }, faults,
    connect(value) {base=value;},
    allowCallback(value) {
      if(value===null){callback=undefined;return;}
      const target=new URL(value);
      assert.equal(target.protocol,'https:');assert.equal(target.hostname,'app.example');
      assert.equal(target.port,String(server.address().port));
      assert.equal(target.username+target.password+target.search+target.hash,'');
      assert.notEqual(target.pathname,'/');callback=target.href;
    },
    capturedCallbacks() {return callbackCaptures;}, mode(value) {mode=value;},
    lastKid() {return lastKid;}, lastClaims() {return lastClaims;},
    authentication() {return {...clientAuthentication};},
    async replayCode() {
      assert.equal(Boolean(firstRequest),true,'successful original code POST must exist');
      const response = await fetch(base+firstRequest.path,{method:'POST',redirect:'error',signal:AbortSignal.timeout(5000),
        headers:{Authorization:firstRequest.authorization,'Content-Type':'application/x-www-form-urlencoded'},body:firstRequest.body});
      assert.equal(response.status,400,'actual original code and verifier must reject reuse');
      const value = await response.json();assert.equal(value.error,'invalid_grant');
      return true;
    },
    async close() {
      server.closeAllConnections();
      await new Promise(resolve=>server.close(resolve));
      firstRequest?.body.fill(0);firstRequest=null;captured=null;lastClaims=null;
    }
  };
}
module.exports = {start};
