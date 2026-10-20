'use strict';
const assert=require('node:assert/strict');

async function client(browser,origin,provider) {
  const context=await browser.newContext({ignoreHTTPSErrors:true});
  const allowed=new Set([origin,new URL(provider.issuer).origin]);
  let unexpected=0,pageErrors=0,returned,authorization;
  await context.route('**/*',async route=>{
    if(allowed.has(new URL(route.request().url()).origin))await route.continue();
    else{unexpected++;await route.abort();}
  });
  const page=await context.newPage();page.on('pageerror',()=>pageErrors++);
  page.on('request',request=>{
    const url=new URL(request.url());
    if(url.origin===origin&&url.pathname==='/oidc/callback')returned=url.href;
  });
  function actionPath(kind,action){return origin+(kind==='signin'?'/v1/oidc/sign-in/':'/v1/account/provider-delete/')+action;}
  async function begin(kind='signin') {
    returned=null;
    await context.clearCookies({domain:'fixture.invalid'});
    await page.goto(origin+(kind==='signin'?'/oidc/sign-in':'/oidc/account-delete'));
    if(kind==='delete')await page.locator('#confirmation').fill('delete my account');
    const response=page.waitForResponse(r=>r.url()===actionPath(kind,'start'));
    await page.locator(kind==='signin'?'#continue':'#confirm').click();
    assert.equal((await response).status(),200,'actual configured start must succeed');
    await page.waitForURL(url=>url.origin===new URL(provider.issuer).origin&&url.pathname.endsWith('/protocol/openid-connect/auth'));
    authorization=new URL(page.url());
    assert.equal(authorization.searchParams.get('redirect_uri'),origin+'/oidc/callback');
    assert.equal(authorization.searchParams.get('code_challenge_method'),'S256');
    assert.equal(authorization.searchParams.has('code_verifier'),false);assert.equal(authorization.searchParams.get('scope'),'openid');
    if(kind==='delete'){assert.equal(authorization.searchParams.get('prompt'),'login');assert.equal(authorization.searchParams.get('max_age'),'0');}
    else{assert.equal(authorization.searchParams.has('prompt'),false);assert.equal(authorization.searchParams.has('max_age'),false);}
  }
  async function login(person=provider,kind='signin') {
    await page.locator('#username').fill(person.username);await page.locator('#password').fill(person.password);
    await page.locator('#kc-login').click();
    await page.waitForFunction(()=>document.getElementById('status')?.textContent.startsWith('Provider returned.'));
    assert.equal(page.url(),origin+'/oidc/callback','callback URL is scrubbed before confirmation');
    assert.equal(typeof returned,'string');
    assert.equal(await page.locator(kind==='signin'?'#signin-form':'#confirm-form').isVisible(),true);
    return returned;
  }
  async function finish(kind,status,onResponse=()=>{}) {
    if(kind==='delete')await page.locator('#confirmation').fill('delete my account');
    const response=page.waitForResponse(r=>r.url()===actionPath(kind,'finish')).then(value=>{onResponse();return value;});
    await page.locator(kind==='signin'?'#continue':'#confirm').click();
    const result=await response;assert.equal(result.status(),status,'only precise application outcome counts');
    const success=kind==='signin'?'Provider sign-in completed.':'Account deletion completed.';
    await page.waitForFunction(success=>{
      const text=document.getElementById('status').textContent;
      return text.startsWith(success)||text.startsWith('The operation was not confirmed.');
    },success);
    assert.equal((await page.locator('#status').innerText()).startsWith(success),status===204);
    return result;
  }
  async function cancel(kind='signin') {
    const response=page.waitForResponse(r=>r.url()===actionPath(kind,'cancel'));
    await page.locator('#cancel').click();assert.equal((await response).status(),204);
    await page.waitForFunction(()=>document.getElementById('status').textContent.startsWith('Pending sign-in cancelled.')||document.getElementById('status').textContent.startsWith('Pending deletion cancelled.'));
  }
  async function close() {
    assert.equal(unexpected,0,'no unrelated browser network access');assert.equal(pageErrors,0);
    assert.equal(await page.evaluate(()=>localStorage.length+sessionStorage.length),0,'application proof never enters storage');
    returned=null;authorization=null;await context.close();
  }
  return {context,page,begin,login,finish,cancel,close,authorization:()=>authorization};
}
async function request(page,path,body) {
  return page.evaluate(async({path,body})=>{
    const response=await fetch(path,{method:body===undefined?'GET':'POST',credentials:'same-origin',cache:'no-store',redirect:'error',
      ...(body===undefined?{}:{headers:{'Content-Type':'application/json'},body:JSON.stringify(body)})});
    const value=response.headers.get('content-type')?.includes('application/json')?await response.json():null;
    return {status:response.status,body:value};
  },{path,body});
}
function finishBody(callback,kind='signin') {
  const query=new URL(callback).searchParams;
  return {state:query.get('state'),code:query.get('code'),issuer:query.get('iss'),...(kind==='delete'?{confirmation:'delete my account'}:{})};
}
function signedClaims(view,provider,proxy,subject) {
  const claims=proxy.lastClaims();
  assert.equal(claims.iss,provider.issuer);assert.equal(claims.sub,subject);
  assert.equal(claims.aud,provider.client);assert.equal(claims.nonce,view.authorization().searchParams.get('nonce'));
  assert.equal(Number.isInteger(claims.auth_time),true,'actual provider authentication time required');
  assert.equal(claims.auth_time<=Date.now()/1000&&Date.now()/1000-claims.auth_time<=300,true);
  assert.equal(claims.exp>Date.now()/1000,true,'test infrastructure: actual token is unexpired');
  return {actual_signed_claim_source:true,exact_issuer_audience_subject_nonce:true,signed_time_present_and_recent:true,token_cap_live:true};
}
module.exports={client,request,finishBody,signedClaims};
