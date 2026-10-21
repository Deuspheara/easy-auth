'use strict';
const assert=require('node:assert/strict');
const {execFileSync}=require('node:child_process');
const owned=require('../oidc/owned-process.cjs');
function start(binary,root,configuration) {
  const state={};
  const process=owned.start(binary,configuration,root,{observe(value){
    if(value.database)state.database=value.database;
    if(value.fixture_database_removed)state.removed=true;
    if(value.facts)state.facts=value.facts;
  }});
  return {...process,state,async close(){
    const result=await process.close();
    let emergency=false;
    if(!state.removed && state.database) {
      assert.match(state.database,/^easy_auth_oidc_[0-9a-f]{32}$/);
      execFileSync(binary,['--remove-owned-database',state.database],{cwd:root,env:global.process.env,stdio:'ignore',timeout:10000});
      emergency=true;
    }
    return {stopped:result.exit===0,database_removed:state.removed===true,emergency_cleanup:emergency,diagnostics:result.diagnostics,facts:state.facts};
  }};
}
module.exports={start};
