'use strict';
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const {createHash} = require('node:crypto');
const {execFileSync} = require('node:child_process');
const {chromium} = require('../passkeys/node_modules/playwright');
const tlsProxy = require('../oidc/proxy.cjs');
const fixture = require('../google-web/fixture.cjs');
const root = path.resolve(__dirname, '../../..');

async function cases(browser, origin, address) {
  const context = await browser.newContext({ignoreHTTPSErrors: true});
  const page = await context.newPage();
  let deliveredWithoutProofs = false, completedWithProofs = false, authorizations = 0;
  const observations = [];
  let deliveries = 0, crossSiteSessionAbsent = true;
  try {
    await context.route('**/*', async route => {
      const requested = new URL(route.request().url());
      if (requested.origin === origin) return route.continue();
      if (requested.origin !== 'https://idp.example' || requested.pathname !== '/sso' || route.request().method() !== 'GET') return route.abort();
      const target = new URL('http://' + address + '/fixture/saml/authorize');
      target.search = requested.search;
      try {
        const response = await context.request.get(target.toString());
        assert.equal(response.status(), 200);
        authorizations++;
        await route.fulfill({status: 200, contentType: 'text/html', body: await response.text()});
      } catch {
        await route.abort(); // Never forward URLs, assertions or provider errors to logs.
      }
    });
    page.on('request', request => {
      const url = new URL(request.url());
      if (url.pathname === '/saml/acs') {
        observations.push(request.allHeaders().then(headers => {
          const cookie = headers.cookie || '';
          deliveredWithoutProofs = !cookie.includes('__Host-auth-saml-');
          deliveries++;
          crossSiteSessionAbsent &&= !cookie.includes('__Host-auth-session=');
        }, () => {}));
      }
      if (url.pathname === '/v1/saml/sign-in/finish') {
        // Header observation is asynchronous; no header/payload is logged.
        observations.push(request.allHeaders().then(headers => {
          const cookie = headers.cookie || '';
          completedWithProofs = cookie.includes('__Host-auth-saml-browser=') && cookie.includes('__Host-auth-saml-relay=');
        }, () => {}));
      }
    });
    await page.goto(origin + '/saml/sign-in');
    await page.getByRole('button', {name: 'Continue with your identity provider'}).click();
    await page.waitForURL('https://idp.example/sso?**');
    await page.getByRole('button', {name: 'Continue', exact: true}).click();
    await page.waitForURL(origin + '/');
    const first = await page.evaluate(async () => {
      const r = await fetch('/v1/session'); return {status: r.status, user: await r.json()};
    });
    assert.equal(first.status, 200);
    assert.equal(first.user.email, null);
    assert.equal(first.user.display_name, 'ordinary-subject');
    await Promise.all(observations);
    assert.equal(deliveredWithoutProofs, true);
    assert.equal(completedWithProofs, true);
    assert.equal(await page.evaluate(() => document.cookie.includes('__Host-auth-')), false);
    const cookies = await context.cookies(origin);
    const session = cookies.find(cookie => cookie.name === '__Host-auth-session');
    assert(session && session.httpOnly && session.secure && session.sameSite === 'Lax');
    assert.equal(cookies.some(cookie => cookie.name.startsWith('__Host-auth-saml-')), false);
    // Existing session must be seen by the same-origin start, not replaced.
    const present = await page.evaluate(async () => (await fetch('/v1/saml/sign-in/start', {method:'POST',headers:{'Content-Type':'application/json'},body:'{}'})).status);
    assert.equal(present, 401);
    assert.equal(authorizations, 1);
    // Restore a genuinely issued session while another SAML operation is at the
    // IdP. This models existing browser authority at finish, without seeding DB
    // authority or constructing a proof. Never serialize its cookie value.
    await context.clearCookies({name: '__Host-auth-session'});
    await page.goto(origin + '/saml/sign-in');
    await page.getByRole('button', {name: 'Continue with your identity provider'}).click();
    await page.waitForURL('https://idp.example/sso?**');
    await context.addCookies([session]);
    const rejected = page.waitForResponse(response => new URL(response.url()).pathname === '/v1/saml/sign-in/finish');
    await page.getByRole('button', {name: 'Continue', exact: true}).click();
    assert.equal((await rejected).status(), 401);
    await page.getByRole('status').filter({hasText: 'Unable to complete sign-in.'}).waitFor();
    const retained = await page.evaluate(async () => (await fetch('/v1/session')).json());
    assert.equal(retained.id, first.user.id);
    const retainedCookie = (await context.cookies(origin)).find(cookie => cookie.name === '__Host-auth-session');
    assert.equal(retainedCookie.value, session.value);
    await Promise.all(observations);
    assert.equal(deliveries, 2);
    assert.equal(deliveredWithoutProofs && crossSiteSessionAbsent, true);
    assert.equal(authorizations, 2);
    await page.evaluate(() => fetch('/v1/logout', {method:'POST'}));
    assert.equal(await page.evaluate(async () => (await fetch('/v1/session')).status), 401);
    return ['cross_site_post_has_no_lax_proofs', 'same_origin_finish_has_private_proofs', 'actual_signed_local_session', 'http_only_cookie_and_proof_cleanup', 'existing_session_cannot_start_again', 'genuine_existing_session_rejected_at_finish', 'original_session_preserved_after_rejection', 'logout_revokes_session'];
  } finally { await context.close(); }
}
async function main() {
  const binary = process.env.EASY_AUTH_SAML_WEB_TEST_BINARY || path.join(root, 'target/debug/examples/saml-web-browser');
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'easy-auth-saml-web-'));
  let proxy, owned, browser, cleanup, results, version, failure, timer;
  try {
    proxy = await tlsProxy.start(directory);
    const origin = 'https://app.example:' + new URL(proxy.origin).port;
    owned = fixture.start(binary, root, origin);
    const address = await Promise.race([owned.ready,new Promise((_,reject)=>{timer=setTimeout(()=>reject(new Error('owned readiness timeout')),30000);})]);
    clearTimeout(timer);
    proxy.connectApplication('http://' + address, origin);
    browser = await chromium.launch({headless:true,args:['--host-resolver-rules=MAP app.example 127.0.0.1']});
    version = browser.version();
    results = await Promise.race([cases(browser,origin,address),new Promise((_,reject)=>{timer=setTimeout(()=>reject(new Error('owned browser deadline')),60000);})]);
  } catch(error) {failure=error;}
  finally {
    clearTimeout(timer);
    for (const action of [async()=>{if(browser)await browser.close();},async()=>{if(owned)cleanup=await owned.close();},async()=>{if(proxy)await proxy.close();}]) {
      try {await action();} catch(error) {failure ||= error;}
    }
    fs.rmSync(directory,{recursive:true,force:true});
  }
  if(failure) {console.log(JSON.stringify({cleanup}));throw failure;}
  assert.deepEqual(cleanup,{stopped:true,database_removed:true,emergency_cleanup:false,diagnostic:false,facts:{users:1,identities:1,sessions:1,audit:2,pending:1,replays:2}});
  const sources = execFileSync('git',['ls-files','--cached','--others','--exclude-standard','-z'],{cwd:root}).toString().split('\0')
    .filter(name => name && !name.includes('/results/') && (/\.(rs|sql|toml|cjs|js|html)$/.test(name) || name==='Cargo.lock')
      && (name.startsWith('crates/') || name.startsWith('apps/') || name.startsWith('tests/support/') || name.startsWith('tests/browser/saml-web/') || name==='Cargo.toml' || name==='Cargo.lock'));
  const report={recorded_at:new Date().toISOString(),node:process.version,chromium:version,playwright:require('../passkeys/node_modules/playwright/package.json').version,
    platform:process.platform,arch:process.arch,source_base_revision:execFileSync('git',['rev-parse','HEAD'],{cwd:root}).toString().trim(),
    source_state:'working tree at recorded base; exact workspace/fixture source hashes below',
    rustc:execFileSync('rustc',['--version'],{cwd:root}).toString().trim(),
    source_sha256:sources.map(name=>({path:name,sha256:createHash('sha256').update(fs.readFileSync(path.join(root,name))).digest('hex')})),
    fixture_binary_sha256:createHash('sha256').update(fs.readFileSync(binary)).digest('hex'),cases:results,cleanup,private_tls_files_removed:true,
    limitations:['Owned Chromium/private TLS with context-only trust exception; no production TLS exception',
      'IdP HTTPS navigation fulfilled only in this context using the established library producer and unchanged public fixtures',
      'Not deployed IdP interoperability, independent audit, complete lifecycle or production activation']};
  if(process.env.EASY_AUTH_SAML_WEB_TEST_REPORT) {
    fs.mkdirSync(path.dirname(process.env.EASY_AUTH_SAML_WEB_TEST_REPORT),{recursive:true});
    fs.writeFileSync(process.env.EASY_AUTH_SAML_WEB_TEST_REPORT,JSON.stringify(report,null,2)+'\n',{flag:'wx'});
  }
  console.log(JSON.stringify({passed:results.length,chromium:version,fixture_database_removed:cleanup.database_removed}));
}
main().catch(error=>{console.error('Owned SAML browser suite failed:',error.name);process.exitCode=1;});
