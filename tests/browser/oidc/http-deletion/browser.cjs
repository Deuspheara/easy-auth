'use strict';
const assert=require('node:assert/strict');

async function client(browser,origin,issuer) {
  const context=await browser.newContext({ignoreHTTPSErrors:true});
  const allowed=new Set([origin,new URL(issuer).origin]);
  let unexpected=0,pageErrors=0,returned;
  await context.route('**/*',async route=>{
    if(allowed.has(new URL(route.request().url()).origin))await route.continue();
    else {unexpected++;await route.abort();}
  });
  const page=await context.newPage();
  page.on('pageerror',()=>pageErrors++);
  page.on('request',request=>{
    const url=new URL(request.url());
    if(url.origin===origin && url.pathname==='/oidc/account-delete/callback')returned=url.href;
  });
  async function begin() {
    // Fresh provider browser state guarantees editable login for the chosen owned
    // user. Application session/proof cookies remain untouched.
    await context.clearCookies({domain:'fixture.invalid'});
    await page.goto(origin+'/oidc/account-delete');
    await page.locator('#confirmation').fill('delete my account');
    const response=page.waitForResponse(r=>r.url()===origin+'/v1/account/provider-delete/start');
    await page.locator('#confirm').click();
    assert.equal((await response).status(),200);
    await page.waitForURL(url=>url.origin===new URL(issuer).origin && url.pathname.endsWith('/protocol/openid-connect/auth'));
    const authorization=new URL(page.url());
    assert.equal(authorization.searchParams.get('max_age'),'0');
    assert.equal(authorization.searchParams.get('prompt'),'login');
    assert.equal(authorization.searchParams.get('code_challenge_method'),'S256');
    assert.equal(authorization.searchParams.has('code_verifier'),false);
  }
  async function login(person) {
    returned=null;
    await page.locator('#username').fill(person.username);
    await page.locator('#password').fill(person.password);
    await page.locator('#kc-login').click();
    await page.waitForFunction(()=>document.getElementById('status')?.textContent.startsWith('Provider returned.'));
    assert.equal(page.url(),origin+'/oidc/account-delete/callback','actual callback URL is immediately scrubbed');
    assert.equal(typeof returned,'string','actual callback GET was observed');
    assert.equal(await page.locator('#confirm-form').isVisible(),true);
    return returned;
  }
  async function finish(status) {
    await page.locator('#confirmation').fill('delete my account');
    const response=page.waitForResponse(r=>r.url()===origin+'/v1/account/provider-delete/finish');
    await page.locator('#confirm').click();
    const result=await response;
    assert.equal(result.status(),status,'only the precise HTTP outcome counts');
    await page.waitForFunction(()=>document.getElementById('status').textContent.startsWith('Account deletion completed.')||document.getElementById('status').textContent.startsWith('The operation was not confirmed.'));
    assert.equal((await page.locator('#status').innerText()).startsWith('Account deletion completed.'),status===204);
    return result;
  }
  async function close() {
    try {
      assert.equal(unexpected,0,'no unrelated browser network access');assert.equal(pageErrors,0);
      assert.equal(await page.evaluate(()=>localStorage.length+sessionStorage.length),0);
    } finally {returned=null;await context.close();}
  }
  return {context,page,begin,login,finish,close};
}
async function request(page,path,body) {
  return page.evaluate(async ({path,body})=>{
    const response=await fetch(path,{method:body===undefined?'GET':'POST',credentials:'same-origin',cache:'no-store',redirect:'error',
      ...(body===undefined?{}:{headers:{'Content-Type':'application/json'},body:JSON.stringify(body)})});
    return response.status;
  },{path,body});
}
function finishBody(callback) {
  const params=new URL(callback).searchParams;
  return {confirmation:'delete my account',state:params.get('state'),code:params.get('code'),issuer:params.get('iss')};
}
module.exports={client,request,finishBody};
