'use strict';
const assert=require('node:assert/strict');
const crypto=require('node:crypto');
const fs=require('node:fs');
const os=require('node:os');
const path=require('node:path');
const {execFileSync}=require('node:child_process');
const {chromium}=require('../../passkeys/node_modules/playwright');
const keycloak=require('../keycloak.cjs');
const tlsProxy=require('../proxy.cjs');
const nativeFixture=require('../fixture.cjs');
const {run}=require('./cases.cjs');
const root=path.resolve(__dirname,'../../../..');

async function main() {
  assert.equal(['darwin','linux'].includes(process.platform),true,'owned process groups require Unix');
  const directory=fs.mkdtempSync(path.join(os.tmpdir(),'easy-auth-oidc-http-'));fs.chmodSync(directory,0o700);
  const binary=process.env.EASY_AUTH_OIDC_HTTP_TEST_BINARY||path.join(root,'target/debug/examples/oidc-deletion-http');
  const database_name='easy_auth_oidc_'+crypto.randomUUID().replaceAll('-','');
  let proxy,provider,fixture,browser,results,version,failure;
  let providerRemoved=false,privateFilesRemoved=false;
  try {
    proxy=await tlsProxy.start(directory);
    const origin='https://app.example:'+new URL(proxy.origin).port;
    const redirect=origin+'/oidc/account-delete/callback';
    provider=await keycloak.start(directory,proxy.origin,redirect);proxy.connect(provider.base);
    await provider.reauthenticationClaims();
    fixture=nativeFixture.start(binary,{database_name,issuer:provider.issuer,client:provider.client,
      secret:provider.secret,redirect,subject:provider.subject,address:proxy.address,
      certificate_der:proxy.certificate_der},root,{httpDeletionCases:true});
    await fixture.ready;
    assert.equal(fixture.state.http_deletion_capability,true,'HTTP-enabled native producer required');
    proxy.connectApplication('http://'+fixture.state.application_address,origin);
    browser=await chromium.launch({headless:true,args:[
      '--host-resolver-rules=MAP fixture.invalid 127.0.0.1, MAP app.example 127.0.0.1, MAP * ~NOTFOUND','--no-proxy-server']});
    version=browser.version();results=await run(fixture,provider,proxy,browser,origin,redirect);
  }catch(error){failure=error;}
  finally {
    try{if(browser)await browser.close();}catch(error){failure||=error;}
    try{if(fixture)await fixture.close();}catch(error){failure||=error;}
    try{if(provider){provider.stop();providerRemoved=true;}}catch(error){failure||=error;}
    try{if(proxy)await proxy.close();}catch(error){failure||=error;}
    try{fs.rmSync(directory,{recursive:true,force:true});privateFilesRemoved=true;}catch(error){failure||=error;}
  }
  const cleanup={fixture_database_removed:fixture?.state.removed===true,provider_container_removed:providerRemoved,
    private_files_removed:privateFilesRemoved,fixture_exit:fixture?.state.exit,
    emergency_database_cleanup:fixture?.state.emergency_database_cleanup===true,
    unexpected_native_diagnostics:fixture?.state.diagnostics===true};
  if(failure){console.log(JSON.stringify(cleanup));throw failure;}
  for(const field of ['fixture_database_removed','provider_container_removed','private_files_removed'])assert.equal(cleanup[field],true);
  assert.equal(cleanup.fixture_exit,0);assert.equal(cleanup.emergency_database_cleanup,false);assert.equal(cleanup.unexpected_native_diagnostics,false);
  assert.equal(results.length,6);
  const sources=execFileSync('git',['ls-files','--cached','--others','--exclude-standard','-z'],{cwd:root})
    .toString().split('\0').filter(name=>name&&!name.includes('/results/')&&
      (/\.(rs|sql|toml|cjs|js|html|json|yml|yaml)$/.test(name)||name==='Cargo.lock'));
  const report={recorded_at:new Date().toISOString(),node:process.version,playwright:require('../../passkeys/node_modules/playwright/package.json').version,
    chromium:version,platform:process.platform,arch:process.arch,provider_image:provider.image,
    source_base_revision:execFileSync('git',['rev-parse','HEAD'],{cwd:root}).toString().trim(),
    fixture_binary_sha256:crypto.createHash('sha256').update(fs.readFileSync(binary)).digest('hex'),
    source_sha256:sources.map(name=>({path:name,sha256:crypto.createHash('sha256').update(fs.readFileSync(path.join(root,name))).digest('hex')})),
    boundary:'actual Keycloak login and reauthentication; real HTTP deletion/reference pages, protected cookies and PostgreSQL commit; production core verifier, repository and HTTPS GET/POST transport; owned TLS proxy and certificate/address mapping only',
    limitations:['initial session uses actual signed core login and a one-use fixture-only cookie-delivery capability, not an ordinary provider login route',
      'controlled token unavailability is injected at the owned TLS proxy; it must return 503 and grants no expected authorization success',
      'finite verified-port observations forward opaque proof unchanged and preserve the real PostgreSQL result',
      'email-free account; no provider-contact SMTP, production-provider interoperability, independent audit or ordinary activation evidence'],
    cases:results,proxy:proxy.facts,controlled_faults:proxy.faults,database:fixture.state.http_facts,...cleanup};
  if(process.env.EASY_AUTH_TEST_REPORT)fs.writeFileSync(process.env.EASY_AUTH_TEST_REPORT,JSON.stringify(report,null,2)+'\n',{flag:'wx',mode:0o600});
  console.log(JSON.stringify({passed:results.length,chromium:version,proxy:proxy.facts,database:fixture.state.http_facts,...cleanup}));
}
main().catch(error=>{
  // Never format browser/native messages, response data, cookies, credentials or IPC.
  const frame=error.stack?.match(/(?:http-deletion\/)?(cases|browser|fixture|keycloak|proxy|run)\.cjs:(\d+)/);
  console.error('Owned OIDC HTTP suite failed:',error.caseName||'startup/cleanup',error.stageName||'case',error.name,frame?frame[1]+':'+frame[2]:'fixture');
  process.exitCode=1;
});
