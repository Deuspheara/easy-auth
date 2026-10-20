'use strict';
const assert=require('node:assert/strict');
const {client}=require('./browser.cjs');
const signin=require('./signin.cjs');
const lifecycle=require('./lifecycle.cjs');

async function run(mode,browser,origin,provider,proxy,owner,restart) {
  const results=[],view=await client(browser,origin,provider);
  const before={...proxy.facts},outages=proxy.faults.unavailable;
  async function record(name,action) {
    name='keycloak-web-'+mode+'-'+name;console.log(JSON.stringify({case:name,status:'running'}));
    try{results.push({name,status:'passed',...await action()});}
    catch(error){error.caseName=name;throw error;}
    console.log(JSON.stringify({case:name,status:'passed'}));
  }
  async function status(expected) {
    const observed=await owner.command('status');assert.equal(observed.result,'facts','database observation must be available');
    assert.equal(observed.source_current,true);assert.equal(observed.jit_allow,true);
    assert.equal(observed.facts.contacts,0);assert.equal(observed.facts.notices,0);
    for(const [key,value] of Object.entries(expected))assert.equal(observed.facts[key],value,'exact committed '+key);
    return observed.facts;
  }
  try {
    const scenario={view,mode,provider,proxy,owner,record,status,origin,restart};
    await signin.run(scenario);await lifecycle.run(scenario);
    assert.equal(results.length,9);
    assert.deepEqual(Object.fromEntries(Object.entries(proxy.facts).map(([key,value])=>[key,value-before[key]])),
      {posts:6,token_responses:5,signature_mutations:0,token_replays:0});
    assert.equal(proxy.faults.unavailable-outages,1);
    const facts=await status({users:0,sessions:0,live_sessions:0,identities:0,audit:4,pending:0,cooldown:1,live_cooldown:1,retained_subjects:0});
    return {mode,cases:results,database:facts};
  }finally{await view.close();}
}
module.exports={run};
