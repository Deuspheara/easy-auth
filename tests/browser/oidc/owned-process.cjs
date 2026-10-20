'use strict';
const assert=require('node:assert/strict');
const {spawn}=require('node:child_process');
const readline=require('node:readline');

// Bounded private JSON pipes and exact owned process-group lifetime only. Domain
// capabilities, database ownership and expected application facts stay with callers.
function start(binary,configuration,root,{args=[],environment=process.env,observe=()=>{}}={}) {
  const child=spawn(binary,args,{cwd:root,env:environment,detached:true,stdio:['pipe','pipe','pipe']});
  const state={diagnostics:false,exit:null};
  let sequence=0,pending,readyResolve,readyReject;
  const ready=new Promise((resolve,reject)=>{readyResolve=resolve;readyReject=reject;});
  const lines=readline.createInterface({input:child.stdout});
  child.stderr.on('data',()=>{state.diagnostics=true;});
  lines.on('line',line=>{
    try {
      const value=JSON.parse(line);observe(value);
      if(value.ready)readyResolve(value);
      if(pending&&value.id===pending.id){pending.resolve(value);pending=null;}
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
  child.stdin.on('error',()=>{/* exact exit receipt is checked by the owner */});
  child.stdin.write(JSON.stringify(configuration)+'\n');
  const bounded=(promise,millis)=>Promise.race([promise,new Promise((_,reject)=>{
    const timer=setTimeout(()=>reject(new Error('owned fixture timeout')),millis);timer.unref();
  })]);
  return {state,ready:bounded(ready,30000),
    async command(command,values={}) {
      assert.equal(Boolean(pending),false,'fixture commands are sequential');
      const id=++sequence;
      const result=new Promise((resolve,reject)=>{pending={id,resolve,reject};});
      child.stdin.write(JSON.stringify({command,id,...values})+'\n');
      return bounded(result,35000);
    },
    async close() {
      child.stdin.end(JSON.stringify({command:'close'})+'\n');
      try{state.exit=await bounded(exited,10000);}
      catch {
        try{process.kill(-child.pid,'SIGKILL');}catch{/* exact group may have exited */}
        child.stdout.destroy();child.stderr.destroy();state.exit='timeout';
      }
      lines.close();return state;
    }
  };
}
module.exports={start};
