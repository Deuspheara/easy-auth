'use strict';
const assert = require('node:assert/strict');
const {spawn,execFileSync} = require('node:child_process');
const readline = require('node:readline');

function start(binary, configuration, root, {identityCases=false}={}) {
  const child = spawn(binary,[],{cwd:root,env:process.env,detached:true,stdio:['pipe','pipe','pipe']});
  const state = {removed:false,created:false,diagnostics:false,facts:null};
  let sequence = 0, pending, readyResolve, readyReject;
  const ready = new Promise((resolve,reject)=>{readyResolve=resolve;readyReject=reject;});
  const lines = readline.createInterface({input:child.stdout});
  child.stderr.on('data',()=>{state.diagnostics=true;});
  lines.on('line',line=>{
    try {
      const value=JSON.parse(line);
      if (value.database_created) {assert.equal(value.database_created,configuration.database_name);state.created=true;}
      if (['database_migration','connection_configuration','tls_configuration','document_configuration','exchange_configuration'].includes(value.phase)) state.phase=value.phase;
      if (value.ready) {state.identity_capability=value.identity_capability===true;readyResolve();}
      if (['active_connections','missing_database','storage_failure'].includes(value.cleanup_failure)) state.cleanup_failure=value.cleanup_failure;
      if (value.database_removed) state.removed=true;
      if (value.facts) state.facts=value.facts;
      if (value.identity_facts) state.identity_facts=value.identity_facts;
      if (pending && value.id===pending.id) {pending.resolve(value);pending=null;}
    } catch {
      const error=new Error('invalid private fixture IPC');
      readyReject(error);pending?.reject(error);pending=null;
    }
  });
  child.on('error',()=>readyReject(new Error('fixture spawn failed')));
  const exited=new Promise(resolve=>child.on('close',code=>{
    readyReject(new Error('fixture stopped before readiness'));
    pending?.reject(new Error('fixture stopped during command'));pending=null;
    resolve(code);
  }));
  child.stdin.on('error',()=>{ /* close is checked by the owned exit receipt */ });
  child.stdin.write(JSON.stringify(configuration)+'\n');
  const bounded=(promise,millis)=>Promise.race([promise,new Promise((_,reject)=>{
    const timer=setTimeout(()=>reject(new Error('owned fixture timeout')),millis);timer.unref();
  })]);
  return {state,ready:bounded(ready,30000).catch(error=>{error.stageName=state.phase;throw error;}),
    async command(command,values={}) {
      assert.equal(Boolean(pending),false,'fixture commands are sequential');
      const id=++sequence;
      const result=new Promise((resolve,reject)=>{pending={id,resolve,reject};});
      child.stdin.write(JSON.stringify({command,id,...values})+'\n');
      return bounded(result,35000);
    },
    async close() {
      child.stdin.end(JSON.stringify({command:'close'})+'\n');
      let code;
      try {code=await bounded(exited,10000);}
      catch {
        try {process.kill(-child.pid,'SIGKILL');} catch { /* exact owned group may have exited */ }
        child.stdout.destroy();child.stderr.destroy();
        code='timeout';
      }
      state.exit=code;
      lines.close();
      if (!state.removed) {
        execFileSync(binary,['--remove-owned-database',configuration.database_name],
          {cwd:root,env:process.env,stdio:['ignore','pipe','pipe'],timeout:10000});
        state.emergency_database_cleanup=true;
      }
      assert.equal(code,0,'owned fixture must exit normally');
      assert.equal(state.removed,true,'normal database-removal receipt required');
      assert.equal(state.diagnostics,false,'no unexpected native diagnostics');
      assert.deepEqual(state.facts,identityCases?{users:2,sessions:4,audit:4,pending:0}:{users:0,sessions:0,audit:0,pending:0});
      if(identityCases)assert.deepEqual(state.identity_facts,{identities:1,provider_users:1,provider_contacts:0,oidc_sessions:3,weak_provider_sessions:0});
    }
  };
}
module.exports={start};
