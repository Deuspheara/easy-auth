'use strict';
const assert=require('node:assert/strict');
const crypto=require('node:crypto');
const fs=require('node:fs');
const path=require('node:path');
const {execFileSync}=require('node:child_process');
const owned=require('../owned-process.cjs');

function startOwner(binary,root,provider,origin) {
  const configuration={database_name:'easy_auth_oidc_'+crypto.randomUUID().replaceAll('-',''),
    realm:crypto.randomUUID(),connection:crypto.randomUUID(),local_client:crypto.randomUUID(),issuer:provider.issuer,provider_client:provider.client,redirect:origin+'/oidc/callback'};
  const state={created:false,removed:false};
  const pipe=owned.start(binary,configuration,root,{args:['--database-owner'],observe(value){
    if(value.database_created){assert.equal(value.database_created,configuration.database_name);state.created=true;}
    if(value.database_removed)state.removed=true;
  }});
  return {configuration,state,ready:pipe.ready.then(value=>{assert.equal(value.database_owner,true);}),command:pipe.command,
    async close(){
      const stopped=await pipe.close();
      if(!state.removed){
        execFileSync(binary,['--remove-owned-database',configuration.database_name],{cwd:root,env:process.env,stdio:['ignore','pipe','pipe'],timeout:10000});
        state.emergency_cleanup=true;
      }
      assert.equal(stopped.exit,0,'owned database observer must exit normally');assert.equal(stopped.diagnostics,false);
      assert.equal(state.removed,true,'normal owned database-removal receipt required');assert.equal(Boolean(state.emergency_cleanup),false);
    }
  };
}
function startApplication(binary,root,mode,owner,provider,proxy,directory,origin) {
  const database=new URL(process.env.DATABASE_URL);
  assert.equal(['localhost','127.0.0.1','[::1]'].includes(database.hostname),true,'owned loopback database required');
  database.pathname='/'+owner.configuration.database_name;
  const secret=path.join(directory,mode+'-client-secret');
  if(fs.existsSync(secret)){
    assert.equal(fs.statSync(secret).isFile(),true);
    assert.equal(fs.readFileSync(secret,'utf8')===provider.secret,true,'restart retains the exact owned protected credential file');
  }else fs.writeFileSync(secret,provider.secret,{mode:0o600,flag:'wx'});
  const environment=Object.fromEntries(Object.entries(process.env).filter(([key])=>!key.startsWith('AUTH_')&&!key.startsWith('SMTP_')));
  Object.assign(environment,{DATABASE_URL:database.href,AUTH_DEVELOPMENT:'true',AUTH_PUBLIC_URL:origin,
    AUTH_BIND:'127.0.0.1:0',AUTH_REALM_ID:owner.configuration.realm,SMTP_HOST:'127.0.0.1',SMTP_PORT:'1025',SMTP_FROM:'auth@localhost.test',
    AUTH_OIDC_ENABLED:'true',AUTH_OIDC_CONNECTION_ID:owner.configuration.connection,AUTH_OIDC_LOCAL_CLIENT_ID:owner.configuration.local_client,
    AUTH_OIDC_ISSUER:provider.issuer,AUTH_OIDC_PROVIDER_CLIENT_ID:provider.client,AUTH_OIDC_ALLOWED_ORIGINS:new URL(provider.issuer).origin,
    AUTH_OIDC_CLIENT_AUTH_METHOD:'client_secret_basic',AUTH_OIDC_CLIENT_SECRET_FILE:secret,AUTH_OIDC_SIGNING_ALGORITHMS:'RS256',AUTH_OIDC_JIT:'allow'});
  const state={stopped:false};
  const pipe=owned.start(binary,{mode,issuer:provider.issuer,address:proxy.address,certificate_der:proxy.certificate_der},root,
    {environment,observe(value){if(value.server_stopped)state.stopped=true;}});
  return {state,ready:pipe.ready.then(value=>{
    assert.equal(value.public_login_only,true);assert.equal(value.auth_only_refused,true);
    assert.match(value.application_address,/^127\.0\.0\.1:\d+$/);return value.application_address;
  }),async close(){
    const stopped=await pipe.close();assert.equal(stopped.exit,0,'configured application must exit normally');
    assert.equal(stopped.diagnostics,false);assert.equal(state.stopped,true,'actual server shutdown receipt required');
  }};
}
module.exports={startOwner,startApplication};
