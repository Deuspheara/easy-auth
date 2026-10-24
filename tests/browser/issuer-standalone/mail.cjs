'use strict';
const assert=require('node:assert/strict');
const crypto=require('node:crypto');
function mailbox(base) {
  const url=new URL(base);assert.equal(url.protocol,'http:');
  assert.equal(['localhost','127.0.0.1','[::1]'].includes(url.hostname),true);
  const address=`issuer-${crypto.randomUUID()}@example.test`;
  const ids=new Set();
  async function request(path,options) {
    const r=await fetch(new URL(path,url),{...options,signal:AbortSignal.timeout(5000)});
    assert.equal(r.ok,true,'owned Mailpit request');return r;
  }
  async function messages() {
    const data=await (await request('/api/v1/search?query='+encodeURIComponent('to:'+address))).json();
    return data.messages.filter(m=>m.To.length===1&&m.To[0].Address===address);
  }
  return {address,
    async proof(origin) {
      const deadline=Date.now()+10000;
      while(Date.now()<deadline) {
        for(const summary of await messages()) {
          if(summary.Subject!=='Your sign-in link'||ids.has(summary.ID))continue;
          ids.add(summary.ID);
          const message=await (await request('/api/v1/message/'+encodeURIComponent(summary.ID))).json();
          assert.equal(message.To.length===1&&message.To[0].Address===address,true);
          const match=message.Text.match(/https:\/\/fixture\.invalid:\d+\/#token=([A-Za-z0-9_-]{43})/);
          assert.equal(Boolean(match),true,'actual SMTP sign-in proof');
          assert.equal(new URL(match[0]).origin,origin);return match[1];
        }
        await new Promise(resolve=>setTimeout(resolve,100));
      }
      throw new Error('owned sign-in message timeout');
    },
    async cleanup() {
      for(const summary of await messages())ids.add(summary.ID);
      if(ids.size)await request('/api/v1/messages',{method:'DELETE',headers:{'Content-Type':'application/json'},body:JSON.stringify({IDs:[...ids]})});
      assert.equal((await messages()).length,0);
      return ids.size;
    }
  };
}
module.exports={mailbox};
