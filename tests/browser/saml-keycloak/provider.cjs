'use strict';
const assert=require('node:assert/strict');
const {X509Certificate}=require('node:crypto');

async function configure(provider,origin) {
  const client='urn:example:sp';
  await provider.admin('/clients','POST',{
    clientId:client,enabled:true,protocol:'saml',redirectUris:[origin+'/saml/acs'],
    adminUrl:origin+'/saml/acs',frontchannelLogout:false,
    attributes:{
      'saml_name_id_format':'persistent','saml_force_name_id_format':'true',
      'saml.force.post.binding':'true','saml.authnstatement':'true',
      'saml.server.signature':'true','saml.assertion.signature':'true',
      'saml.signature.algorithm':'RSA_SHA256',
      'saml_signature_canonicalization_method':'http://www.w3.org/2001/10/xml-exc-c14n#',
      'saml.client.signature':'false','saml.encrypt':'false','saml.assertion.lifespan':'180',
      'saml_assertion_consumer_url_post':origin+'/saml/acs'
    }
  });
  const clients=await provider.admin('/clients?clientId='+encodeURIComponent(client));
  assert.equal(clients.length,1);
  const actual=await provider.admin('/clients/'+clients[0].id);
  for(const [name,value] of Object.entries({'saml.server.signature':'true','saml.assertion.signature':'true','saml.signature.algorithm':'RSA_SHA256','saml_name_id_format':'persistent'})) {
    assert.equal(actual.attributes[name],value,'ordinary IdP profile persisted');
  }
}
async function active(provider) {
  const keys=await provider.admin('/keys');
  const key=keys.keys.find(key=>key.kid===keys.active.RS256 && key.use==='SIG');
  assert(key && key.certificate && key.providerId,'actual active provider certificate');
  const der=Buffer.from(key.certificate,'base64');
  const certificate=new X509Certificate(der);
  const now=Math.floor(Date.now()/1000);
  const from=Math.max(now-5,Math.ceil(Date.parse(certificate.validFrom)/1000));
  const until=Math.min(now+3600,Math.floor(Date.parse(certificate.validTo)/1000));
  assert(from<=now && until>now,'explicit approval within actual certificate validity');
  return {kid:key.kid,component:key.providerId,pin:{der:Array.from(der),from,until}};
}
async function activeComponent(provider,id,enabled) {
  const component=await provider.admin('/components/'+id);
  component.config.active=[String(enabled)];
  await provider.admin('/components/'+id,'PUT',component);
}
module.exports={configure,active,activeComponent};
