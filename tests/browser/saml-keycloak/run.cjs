'use strict';
const assert=require('node:assert/strict');
const fs=require('node:fs');
const os=require('node:os');
const path=require('node:path');
const {createHash}=require('node:crypto');
const {execFileSync}=require('node:child_process');
const {chromium}=require('../passkeys/node_modules/playwright');
const keycloak=require('../oidc/keycloak.cjs');
const tls=require('../oidc/proxy.cjs');
const fixture=require('./fixture.cjs');
const providerProfile=require('./provider.cjs');
const deletion=process.argv.includes('--account-deletion');
const cases=deletion?require('./deletion/cases.cjs'):require('./cases.cjs');
const root=path.resolve(__dirname,'../../..');
async function main() {
  const binary=process.env.EASY_AUTH_SAML_KEYCLOAK_BINARY||path.join(root,'target/debug/examples/saml-keycloak-browser');
  const directory=fs.mkdtempSync(path.join(os.tmpdir(),'easy-auth-saml-keycloak-'));fs.chmodSync(directory,0o700);
  let proxy,provider,owner,browser,cleanup,result,version,failure,timer,removed=false;
  try {
    proxy=await tls.start(directory);
    const origin='https://app.example:'+new URL(proxy.origin).port;
    provider=await keycloak.start(directory,proxy.origin,origin+'/unused-oidc-callback');proxy.connect(provider.base);
    await providerProfile.configure(provider,origin);
    const initial=await providerProfile.active(provider);
    owner=fixture.start(binary,root,{origin,issuer:provider.issuer,certificates:[initial.pin],jit:'deny'});
    const ready=await owner.ready;proxy.connectApplication('http://'+ready.address,origin);
    browser=await chromium.launch({headless:true,args:['--host-resolver-rules=MAP fixture.invalid 127.0.0.1, MAP app.example 127.0.0.1, MAP * ~NOTFOUND','--no-proxy-server']});
    version=browser.version();
    result=await Promise.race([cases.run(owner,provider,browser,origin,initial),new Promise((_,reject)=>{timer=setTimeout(()=>reject(new Error('ordinary provider acceptance deadline')),120000);})]);
  } catch(error) {failure=error;}
  finally {
    clearTimeout(timer);
    for(const action of [async()=>{if(browser)await browser.close();},async()=>{if(owner)cleanup=await owner.close();},async()=>{if(provider){provider.stop();removed=true;}},async()=>{if(proxy)await proxy.close();}]) {
      try {await action();}catch(error){failure ||= error;}
    }
    fs.rmSync(directory,{recursive:true,force:true});
  }
  if(failure) {console.log(JSON.stringify({cleanup,provider_removed:removed}));throw failure;}
  assert.equal(result.cases.length,deletion?7:10);
  assert.equal(cleanup.stopped&&cleanup.database_removed&&!cleanup.emergency_cleanup&&!cleanup.diagnostics&&removed,true);
  const sources=execFileSync('git',['ls-files','--cached','--others','--exclude-standard','-z'],{cwd:root}).toString().split('\0').filter(n=>n&&!n.includes('/results/')&&(/\.(rs|sql|toml|cjs|js|html)$/.test(n)||n==='Cargo.lock')&&(n.startsWith('crates/')||n.startsWith('apps/')||n.startsWith('tests/support/')||n.startsWith('tests/browser/saml-keycloak/')||n.startsWith('tests/browser/oidc/')||n==='Cargo.lock'||n==='Cargo.toml'));
  const report={recorded_at:new Date().toISOString(),node:process.version,chromium:version,playwright:require('../passkeys/node_modules/playwright/package.json').version,platform:process.platform,arch:process.arch,provider_image:provider.image,
    source_base_revision:execFileSync('git',['rev-parse','HEAD'],{cwd:root}).toString().trim(),source_state:'working tree source hashes recorded',fixture_binary_sha256:createHash('sha256').update(fs.readFileSync(binary)).digest('hex'),source_sha256:sources.map(n=>({path:n,sha256:createHash('sha256').update(fs.readFileSync(path.join(root,n))).digest('hex')})),
    suite:deletion?'account-deletion':'sign-in-rollover',cases:result.cases,database:result.facts,cleanup,provider_container_removed:removed,private_files_removed:true,
    limitations:['Owned Keycloak and Chromium/private TLS only; context-specific certificate tolerance, no production TLS fallback',
      'Realm and certificate administration are private fixture commands; no proof/identity/session setup bypass',
      'Ordinary provider key rotation, no edited XML or custom cryptographic fixture/probe',
      'No qualified-attribute approval, Entra/Okta claim, independent audit or production activation']};
  if(process.env.EASY_AUTH_SAML_KEYCLOAK_REPORT){fs.mkdirSync(path.dirname(process.env.EASY_AUTH_SAML_KEYCLOAK_REPORT),{recursive:true});fs.writeFileSync(process.env.EASY_AUTH_SAML_KEYCLOAK_REPORT,JSON.stringify(report,null,2)+'\n',{flag:'wx'});}
  console.log(JSON.stringify({passed:result.cases.length,chromium:version,provider_image:provider.image,cleanup}));
}
main().catch(error=>{const frame=error.stack?.match(/(browser|provider|cases|fixture|keycloak|run)\.cjs:(\d+)/);console.error('Owned Keycloak SAML acceptance failed:',error.name,frame?frame[1]+':'+frame[2]:'fixture');process.exitCode=1;});
