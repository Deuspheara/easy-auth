'use strict';
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const {chromium} = require('../passkeys/node_modules/playwright');
const tlsProxy = require('../oidc/proxy.cjs');
const fixture = require('../google-web/fixture.cjs');
const cases = require('./cases.cjs');
const {client} = require('./client.cjs');
const root = path.resolve(__dirname, '../../..');

async function main() {
  const binary = process.env.EASY_AUTH_ISSUER_WEB_TEST_BINARY || path.join(root, 'target/debug/examples/issuer-web-browser');
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'easy-auth-issuer-web-'));
  let proxy, owned, browser, cleanup, passed, failure, timer;
  try {
    proxy = await tlsProxy.start(directory);
    const origin = 'https://app.example:' + new URL(proxy.origin).port;
    owned = fixture.start(binary, root, origin);
    const address = await Promise.race([owned.ready, new Promise((_,reject) => { timer = setTimeout(() => reject(new Error('owned readiness deadline')),30000); })]);
    clearTimeout(timer);
    proxy.connectApplication('http://' + address, origin);
    browser = await chromium.launch({headless:true,args:['--host-resolver-rules=MAP app.example 127.0.0.1']});
    const actor=client(origin,fs.readFileSync(path.join(directory,'fixture.pem')));
    passed = await Promise.race([cases.run(browser,origin,actor),new Promise((_,reject) => { timer = setTimeout(() => reject(new Error('owned browser deadline')),60000); })]);
  } catch (error) { failure = error; }
  finally {
    clearTimeout(timer);
    for (const action of [async () => { if (browser) await browser.close(); }, async () => { if (owned) cleanup = await owned.close(); }, async () => { if (proxy) await proxy.close(); }]) {
      try { await action(); } catch (error) { failure ||= error; }
    }
    fs.rmSync(directory,{recursive:true,force:true});
  }
  if (failure) throw failure;
  assert.deepEqual(cleanup,{stopped:true,database_removed:true,emergency_cleanup:false,diagnostic:false,
    facts:{users:1,sessions:1,subjects:1,consumed:1,access:1,redeemed_audit:1}});
  assert.equal(passed,3);
  console.log(JSON.stringify({passed,database_removed:true,private_tls_files_removed:true}));
}
main().catch(error => { console.error('Owned signed issuer suite failed:',error.name,error.caseName || 'fixture');process.exitCode=1; });
