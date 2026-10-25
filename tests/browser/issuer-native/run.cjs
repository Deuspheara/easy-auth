'use strict';
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const {chromium} = require('../passkeys/node_modules/playwright');
const tlsProxy = require('../oidc/proxy.cjs');
const fixture = require('../google-web/fixture.cjs');
const cases = require('./cases.cjs');
const loopback = require('./listener.cjs');
const root = path.resolve(__dirname, '../../..');

async function main() {
  const binary = process.env.EASY_AUTH_ISSUER_WEB_TEST_BINARY || path.join(root, 'target/debug/examples/issuer-web-browser');
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'easy-auth-issuer-web-'));
  let proxy, owned, browser, cleanup, passed, failure, timer, listener;
  try {
    proxy = await tlsProxy.start(directory);
    const origin = 'https://app.example:' + new URL(proxy.origin).port;
    listener=await loopback.start();
    const previous=process.env.EASY_AUTH_OWNED_ISSUER_NATIVE;
    process.env.EASY_AUTH_OWNED_ISSUER_NATIVE='1';
    try { owned = fixture.start(binary, root, origin); }
    finally { if(previous===undefined)delete process.env.EASY_AUTH_OWNED_ISSUER_NATIVE;else process.env.EASY_AUTH_OWNED_ISSUER_NATIVE=previous; }
    const address = await Promise.race([owned.ready, new Promise((_,reject) => { timer = setTimeout(() => reject(new Error('owned readiness deadline')),30000); })]);
    clearTimeout(timer);
    proxy.connectApplication('http://' + address, origin);
    browser = await chromium.launch({headless:true,args:['--host-resolver-rules=MAP app.example 127.0.0.1']});
    passed = await Promise.race([cases.run(browser,origin,fs.readFileSync(path.join(directory,'fixture.pem')),listener),new Promise((_,reject) => { timer = setTimeout(() => reject(new Error('owned browser deadline')),60000); })]);
  } catch (error) { failure = error; }
  finally {
    clearTimeout(timer);
    for (const action of [async () => { if(listener)await listener.close(); },async () => { if (browser) await browser.close(); }, async () => { if (owned) cleanup = await owned.close(); }, async () => { if (proxy) await proxy.close(); }]) {
      try { await action(); } catch (error) { failure ||= error; }
    }
    fs.rmSync(directory,{recursive:true,force:true});
  }
  if (failure) throw failure;
  assert.deepEqual(cleanup,{stopped:true,database_removed:true,emergency_cleanup:false,diagnostic:false,
    facts:{users:1,sessions:1,subjects:1,consumed:1,access:3,redeemed_audit:1,families:1,refresh:3,revoked_families:1,revoked_access:3}});
  assert.equal(passed,6);
  console.log(JSON.stringify({passed,database_removed:true,private_tls_files_removed:true}));
}
main().catch(error => { console.error('Owned native issuer suite failed:',error.name,error.caseName || 'fixture');process.exitCode=1; });
