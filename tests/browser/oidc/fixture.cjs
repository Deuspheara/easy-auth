'use strict';
const assert = require('node:assert/strict');
const {execFileSync} = require('node:child_process');
const owned = require('./owned-process.cjs');

function start(binary, configuration, root, {identityCases=false,httpDeletionCases=false}={}) {
  assert.equal(identityCases && httpDeletionCases,false,'one owned fixture mode');
  const state = {removed:false,created:false,diagnostics:false,facts:null};
  const pipe=owned.start(binary,configuration,root,{observe(value) {
      if (value.database_created) {assert.equal(value.database_created,configuration.database_name);state.created=true;}
      if (['database_migration','connection_configuration','tls_configuration','document_configuration','exchange_configuration'].includes(value.phase)) state.phase=value.phase;
      if (value.ready) {state.http_deletion_capability=value.http_deletion_capability===true;state.application_address=value.application_address;state.identity_capability=value.identity_capability===true;state.deletion_capability=value.deletion_capability===true;}
      if (['active_connections','missing_database','storage_failure'].includes(value.cleanup_failure)) state.cleanup_failure=value.cleanup_failure;
      if (value.database_removed) state.removed=true;
      if (value.facts) state.facts=value.facts;
      if (value.http_facts) state.http_facts=value.http_facts;
      if (value.identity_facts) state.identity_facts=value.identity_facts;
      if (value.deletion_facts) state.deletion_facts=value.deletion_facts;
  }});
  return {state,ready:pipe.ready.catch(error=>{error.stageName=state.phase;throw error;}),
    command:pipe.command,
    async close() {
      const result=await pipe.close();
      const code=result.exit;state.exit=code;state.diagnostics=result.diagnostics;
      if (!state.removed) {
        execFileSync(binary,['--remove-owned-database',configuration.database_name],
          {cwd:root,env:process.env,stdio:['ignore','pipe','pipe'],timeout:10000});
        state.emergency_database_cleanup=true;
      }
      assert.equal(code,0,'owned fixture must exit normally');
      assert.equal(state.removed,true,'normal database-removal receipt required');
      assert.equal(state.diagnostics,false,'no unexpected native diagnostics');
      assert.deepEqual(state.facts,httpDeletionCases?{users:0,sessions:0,audit:2,pending:0}:identityCases?{users:1,sessions:1,audit:6,pending:0}:{users:0,sessions:0,audit:0,pending:0});
      if(httpDeletionCases) {
        assert.deepEqual(state.http_facts,{users:0,sessions:0,identities:0,audit:2,pending:0,cooldown:1,notices:0,contacts:0,live_cooldown:1,retained_subjects:0});
      }
      if(identityCases) {
        assert.deepEqual(state.identity_facts,{identities:0,provider_users:0,provider_contacts:0,oidc_sessions:0,weak_provider_sessions:0});
        assert.deepEqual(state.deletion_facts,{deleted:1,live_cooldown:1,erased_provider_audits:4,live_mailbox_audits:1});
      }
    }
  };
}
module.exports={start};
