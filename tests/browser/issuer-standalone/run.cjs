'use strict';
const assert=require('node:assert/strict');
const fs=require('node:fs');
const os=require('node:os');
const path=require('node:path');
const crypto=require('node:crypto');
const {execFileSync}=require('node:child_process');
const {chromium}=require('../passkeys/node_modules/playwright');
const proxyFixture=require('../oidc/proxy.cjs');
const owned=require('../oidc/owned-process.cjs');
const {client}=require('../issuer-web/client.cjs');
const {mailbox}=require('./mail.cjs');
const cases=require('./cases.cjs');
const loopback=require('../issuer-native/listener.cjs');
const root=path.resolve(__dirname,'../../..');
async function mode(mode,browser) {
  const directory=fs.mkdtempSync(path.join(os.tmpdir(),'easy-auth-issuer-parity-'));
  fs.chmodSync(directory,0o700);
  const mail=mailbox(process.env.EASY_AUTH_MAILPIT_URL||'http://127.0.0.1:8025');
  let proxy,fixture,report,failure,removed=false,closed,messages,configuration,emergency=false,stage="tls",listener;
  try {
    proxy=await proxyFixture.start(directory);
    listener=await loopback.start();
    const config={mode,directory,native_listener:new URL(listener.origin).host,issuer:proxy.origin,address:proxy.address,certificate_der:proxy.certificate_der,
      database_name:'easy_auth_oidc_'+crypto.randomUUID().replaceAll('-',''),server_binary:path.join(root,'target/debug/easy-auth')};
    configuration=config;
    stage="fixture-startup";
    fixture=owned.start(path.join(root,'target/debug/examples/issuer-client-acceptance'),config,root,{observe(value){if(value.database_removed)removed=true;if(value.phase)stage=value.phase;}});
    fixture.readyValue=await fixture.ready;
    proxy.connect('http://'+fixture.readyValue.application_address);
    const actor=client(proxy.origin,fs.readFileSync(path.join(directory,'fixture.pem')));
    stage="browser-cases";
    report=await cases.run(browser,proxy.origin,fixture,actor,mail,listener);
  } catch(error) {error.stageName ||= stage;failure=error;}
  finally {
    for(const action of [async()=>{if(listener)await listener.close();},async()=>{if(fixture)closed=await fixture.close();},async()=>{if(proxy)await proxy.close();},async()=>{messages=await mail.cleanup();}]) {
      try{await action();}catch(error){failure ||= error;}
    }
    if(configuration&&!removed) {
      try {execFileSync(path.join(root,'target/debug/examples/issuer-client-acceptance'),['--remove-owned-database',configuration.database_name],{cwd:root,env:process.env,stdio:'ignore',timeout:10000});emergency=true;}
      catch(error){failure ||= error;}
    }
    fs.rmSync(directory,{recursive:true,force:true});
  }
  if(failure)throw failure;
  assert.deepEqual(closed,{diagnostics:false,exit:0});assert.equal(removed,true);assert.equal(emergency,false);assert.equal(messages,1);
  return {behavior:report,database_removed:removed,mail_removed:true,private_files_removed:true};
}
async function main() {
  const browser=await chromium.launch({headless:true,args:['--host-resolver-rules=MAP fixture.invalid 127.0.0.1']});
  try {
    const standalone=await mode('standalone',browser);
    const embedded=await mode('embedded',browser);
    assert.deepEqual(standalone,embedded,'same user behavior and cleanup for standalone and embedded');
    console.log(JSON.stringify({standalone,embedded,parity:true}));
  } finally {await browser.close();}
}
main().catch(error=>{console.error('Owned standalone parity acceptance failed:',error.name,error.stageName||'runner',error.caseName||'fixture');process.exitCode=1;});
