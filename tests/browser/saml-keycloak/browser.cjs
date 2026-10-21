'use strict';
const assert=require('node:assert/strict');
async function login(browser,origin,provider,expected=204) {
  const context=await browser.newContext({ignoreHTTPSErrors:true});
  const page=await context.newPage();
  try {
    await context.route('**/*',async route=>{
      try {
        const url=new URL(route.request().url());
        if(url.origin===origin || url.origin===new URL(provider.issuer).origin)await route.continue();
        else await route.abort();
      } catch { /* Closing owned contexts must not print protocol-bearing route errors. Awaited navigation/completion still proves acceptance. */ }
    });
    await page.goto(origin+'/saml/sign-in');
    await page.getByRole('button',{name:'Continue with your identity provider'}).click();
    await page.locator('#username').fill(provider.username);
    await page.locator('#password').fill(provider.password);
    const finished=page.waitForResponse(r=>new URL(r.url()).pathname==='/v1/saml/sign-in/finish');
    await page.locator('#kc-login').click();
    const response=await finished;
    assert.equal(response.status(),expected,'real IdP POST completion');
    if(expected!==204) {await context.close();return null;}
    await page.waitForURL(origin+'/');
    const user=await page.evaluate(async()=>{const r=await fetch('/v1/session');return {status:r.status,user:await r.json()};});
    assert.equal(user.status,200);
    assert.equal(user.user.email,null);
    return {context,page,user:user.user};
  } catch(error) {await context.close();throw error;}
}
async function status(session) {
  return session.page.evaluate(async()=>(await fetch('/v1/session')).status);
}
module.exports={login,status};
