'use strict';
const assert=require('node:assert/strict');
const crypto=require('node:crypto');
const fs=require('node:fs');
const os=require('node:os');
const path=require('node:path');
const {execFileSync}=require('node:child_process');
const {chromium}=require('../passkeys/node_modules/playwright');
const tlsProxy=require('../oidc/proxy.cjs');
const fixture=require('../google-web/fixture.cjs');
const cases=require('./cases.cjs');
const root=path.resolve(__dirname,'../../..');

async function main() {
  const binary=process.env.EASY_AUTH_APPLE_GRANTS_TEST_BINARY||path.join(root,'target/debug/examples/apple-grants-browser');
  const directory=fs.mkdtempSync(path.join(os.tmpdir(),'easy-auth-apple-grants-'));
  let proxy,owned,browser,cleanup,results,version,failure,timer;
  try {
    proxy=await tlsProxy.start(directory);
    const origin='https://app.example:'+new URL(proxy.origin).port;
    owned=fixture.start(binary,root,origin);
    const address=await Promise.race([owned.ready,new Promise((_,reject)=>{timer=setTimeout(()=>reject(new Error('owned readiness timeout')),30000);})]);
    clearTimeout(timer);proxy.connectApplication('http://'+address,origin);
    browser=await chromium.launch({headless:true,args:['--host-resolver-rules=MAP app.example 127.0.0.1']});
    version=browser.version();
    const erase=(session,realm)=>{
      const name=owned.ownedDatabase();assert.match(name,/^easy_auth_oidc_[0-9a-f]{32}$/);
      const url=new URL(process.env.DATABASE_URL);url.pathname='/'+name;
      const executable=process.env.EASY_AUTH_APPLE_GRANT_ERASURE_PROBE||path.join(root,'target/debug/examples/apple-grant-erasure-probe');
      const output=execFileSync(executable,[],{cwd:root,env:{...process.env,DATABASE_URL:url.href},
        input:JSON.stringify({realm,session}),encoding:'utf8',timeout:10000,stdio:['pipe','pipe','pipe']});
      return JSON.parse(output);
    };
    results=await Promise.race([cases.run(browser,origin,erase),new Promise((_,reject)=>{timer=setTimeout(()=>reject(new Error('owned browser deadline')),90000);})]);
  } catch(error) {failure=error;}
  finally {
    clearTimeout(timer);
    for(const action of [async()=>{if(browser)await browser.close();},async()=>{if(owned)cleanup=await owned.close();},async()=>{if(proxy)await proxy.close();}]) {
      try {await action();}catch(error){failure||=error;}
    }
    fs.rmSync(directory,{recursive:true,force:true});
  }
  if(failure){console.log(JSON.stringify({cleanup}));throw failure;}
  assert.equal(cleanup.stopped,true);assert.equal(cleanup.database_removed,true);
  assert.equal(cleanup.emergency_cleanup,false);assert.equal(cleanup.diagnostic,false);
  assert.deepEqual(cleanup.facts,{users:1,identities:0,sessions:2,audit:7,pending:0,google_posts:0,google_signed:0,apple_posts:4,apple_signed:4,
    grants:{active:0,pending:0,leased:0,failed:0,completed:3,expired:0,encrypted:0,attempts:4,calls:4}});
  assert.equal(results.length,9);
  const sources=execFileSync('git',['ls-files','--cached','--others','--exclude-standard','-z'],{cwd:root}).toString().split('\0')
    .filter(name=>name&&!name.includes('/results/')&&(/\.(rs|sql|toml|cjs|js|html|json|yml|yaml|py)$/.test(name)||name==='Cargo.lock'));
  const report={recorded_at:new Date().toISOString(),node:process.version,chromium:version,
    playwright:require('../passkeys/node_modules/playwright/package.json').version,platform:process.platform,arch:process.arch,
    source_base_revision:execFileSync('git',['rev-parse','HEAD'],{cwd:root}).toString().trim(),
    feature_disabled_probe_binary_sha256:crypto.createHash('sha256').update(fs.readFileSync(process.env.EASY_AUTH_APPLE_GRANT_ERASURE_PROBE||path.join(root,'target/debug/examples/apple-grant-erasure-probe'))).digest('hex'),
    fixture_binary_sha256:crypto.createHash('sha256').update(fs.readFileSync(binary)).digest('hex'),
    source_sha256:sources.map(name=>({path:name,sha256:crypto.createHash('sha256').update(fs.readFileSync(path.join(root,name))).digest('hex')})),
    cases:results,cleanup,private_tls_files_removed:true,
    boundary:'Actual owned HTTPS Chromium/reference pages, normal mailbox and signed Apple code completion, real PostgreSQL capture/unlink/leases and actual backoff; offline provider verifies real client-secret signature',
    limitations:['Apple authorization navigation is intercepted only in this owned context; no real provider token/revocation endpoint contacted',
      'Private certificate exception applies only to owned browser context/proxy; no system trust/settings changed',
      'Worker HTTP port is a controlled offline fixture; concrete production HTTPS adapter has separate real-TLS transport evidence',
      'Fixture routes expose finite observations/preconfigured worker only; they are not production routes or authentication proof seeders',
      'No real Apple registration, OS delivery, independent security approval or production-readiness claim']};
  if(process.env.EASY_AUTH_APPLE_GRANTS_TEST_REPORT) {
    fs.mkdirSync(path.dirname(process.env.EASY_AUTH_APPLE_GRANTS_TEST_REPORT),{recursive:true});
    fs.writeFileSync(process.env.EASY_AUTH_APPLE_GRANTS_TEST_REPORT,JSON.stringify(report,null,2)+'\n',{flag:'wx'});
  }
  console.log(JSON.stringify({passed:results.length,chromium:version,fixture_database_removed:cleanup.database_removed}));
}
main().catch(error=>{console.error('Owned Apple grant suite failed:',error.name,error.caseName||'fixture');process.exitCode=1;});
