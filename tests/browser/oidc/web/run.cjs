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
const {startOwner,startApplication}=require('./fixture.cjs');
const cases=require('./cases.cjs');
const root=path.resolve(__dirname,'../../../..');

async function modeRun(mode,binary,provider,proxy,browser,directory,origin,cleanup) {
  let owner,app,result,failure;
  let started=0,stopped=0;
  try {
    owner=startOwner(binary,root,provider,origin);await owner.ready;
    async function start() {
      app=startApplication(binary,root,mode,owner,provider,proxy,directory,origin);started++;
      const address=await app.ready;proxy.connectApplication('http://'+address,origin);
    }
    async function restart() {await app.close();stopped++;await start();}
    await start();
    result=await cases.run(mode,browser,origin,provider,proxy,owner,restart);
  }catch(error){error.stageName||=mode;failure=error;}
  finally {
    try{if(app){await app.close();stopped++;}}catch(error){failure||=error;}
    try{if(owner)await owner.close();}catch(error){failure||=error;}
    cleanup.push({mode,application_stopped:app?.state.stopped===true,database_removed:owner?.state.removed===true,
      emergency_database_cleanup:owner?.state.emergency_cleanup===true,application_instances:started,stopped_instances:stopped});
  }
  if(failure)throw failure;
  return result;
}
async function main() {
  assert.equal(['darwin','linux'].includes(process.platform),true,'owned process groups require Unix');
  const directory=fs.mkdtempSync(path.join(os.tmpdir(),'easy-auth-oidc-web-'));fs.chmodSync(directory,0o700);
  const binary=process.env.EASY_AUTH_OIDC_WEB_TEST_BINARY||path.join(root,'target/debug/examples/oidc-web-native');
  const cleanup=[];let proxy,provider,browser,version,failure;
  const modes=[];let providerRemoved=false,privateFilesRemoved=false;
  try {
    proxy=await tlsProxy.start(directory);
    const origin='https://app.example:'+new URL(proxy.origin).port;
    provider=await keycloak.start(directory,proxy.origin,origin+'/oidc/callback');proxy.connect(provider.base);
    await provider.reauthenticationClaims();
    browser=await chromium.launch({headless:true,args:[
      '--host-resolver-rules=MAP fixture.invalid 127.0.0.1, MAP app.example 127.0.0.1, MAP * ~NOTFOUND','--no-proxy-server']});
    version=browser.version();
    for(const mode of ['standalone','embedded'])modes.push(await modeRun(mode,binary,provider,proxy,browser,directory,origin,cleanup));
  }catch(error){failure=error;}
  finally {
    try{if(browser)await browser.close();}catch(error){failure||=error;}
    try{if(provider){provider.stop();providerRemoved=true;}}catch(error){failure||=error;}
    try{if(proxy)await proxy.close();}catch(error){failure||=error;}
    try{fs.rmSync(directory,{recursive:true,force:true});privateFilesRemoved=true;}catch(error){failure||=error;}
  }
  if(failure){console.log(JSON.stringify({cleanup,provider_container_removed:providerRemoved,private_files_removed:privateFilesRemoved}));throw failure;}
  assert.equal(modes.length,2);assert.equal(modes.every(mode=>mode.cases.length===9),true);
  assert.equal(cleanup.every(mode=>mode.application_stopped&&mode.database_removed&&!mode.emergency_database_cleanup&&mode.application_instances===3&&mode.stopped_instances===3),true);
  assert.equal(providerRemoved&&privateFilesRemoved,true);
  assert.deepEqual(proxy.facts,{posts:12,token_responses:10,signature_mutations:0,token_replays:0});
  assert.deepEqual(proxy.authentication(),{basic:12,post:0,public:0});assert.equal(proxy.faults.unavailable,2);
  const sources=execFileSync('git',['ls-files','--cached','--others','--exclude-standard','-z'],{cwd:root})
    .toString().split('\0').filter(name=>name&&!name.includes('/results/')&&
      (/\.(rs|sql|toml|cjs|js|html|json|yml|yaml|py)$/.test(name)||name==='Cargo.lock'));
  const report={recorded_at:new Date().toISOString(),node:process.version,
    playwright:require('../../passkeys/node_modules/playwright/package.json').version,chromium:version,platform:process.platform,arch:process.arch,
    provider_image:provider.image,source_base_revision:execFileSync('git',['rev-parse','HEAD'],{cwd:root}).toString().trim(),
    fixture_binary_sha256:crypto.createHash('sha256').update(fs.readFileSync(binary)).digest('hex'),
    source_sha256:sources.map(name=>({path:name,sha256:crypto.createHash('sha256').update(fs.readFileSync(path.join(root,name))).digest('hex')})),
    boundary:'unchanged configured application/settings and embedded application-route sources; real public sign-in/callback/finish, protected file client authentication, current-session use/logout and fresh deletion; actual Keycloak/HTTPS/core/PostgreSQL',
    transport_exception:'only the owned example substitutes the concrete transport name with the existing private certificate/address mapping; production has no injection or override',
    limitations:['not a normal-binary public-root TLS positive control or production-provider interoperability',
      'normal binary startup/feature/refusal behavior has separate PostgreSQL smoke evidence',
      'owned database gates observe real final commit and verified subject resolution; no state timing, proof, identity or session is fabricated',
      'email-free path; no provider-contact SMTP, device/browser matrix, independent review or production-readiness claim'],
    cases:modes.flatMap(mode=>mode.cases),modes,proxy:proxy.facts,client_authentication:proxy.authentication(),controlled_faults:proxy.faults,
    cleanup,provider_container_removed:providerRemoved,private_files_removed:privateFilesRemoved};
  if(process.env.EASY_AUTH_TEST_REPORT)fs.writeFileSync(process.env.EASY_AUTH_TEST_REPORT,JSON.stringify(report,null,2)+'\n',{flag:'wx',mode:0o600});
  console.log(JSON.stringify({passed:report.cases.length,chromium:version,proxy:proxy.facts,client_authentication:proxy.authentication(),
    databases:modes.map(mode=>({mode:mode.mode,...mode.database})),cleanup,provider_container_removed:providerRemoved,private_files_removed:privateFilesRemoved}));
}
main().catch(error=>{
  const frame=error.stack?.match(/(?:web\/)?(signin|lifecycle|cases|browser|fixture|keycloak|proxy|owned-process|run)\.cjs:(\d+)/);
  console.error('Owned public OIDC suite failed:',error.caseName||'startup/cleanup',error.stageName||'case',error.name,frame?frame[1]+':'+frame[2]:'fixture');
  process.exitCode=1;
});
