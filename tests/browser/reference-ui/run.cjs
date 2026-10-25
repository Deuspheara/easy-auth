'use strict';
const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const {chromium} = require('../passkeys/node_modules/playwright');
const {withFixture} = require('./fixture.cjs');
const {ownedMail} = require('./mail.cjs');
const {sharedLayout} = require('./refinement.cjs');
const {presentation} = require('./presentation.cjs');
const {motion} = require('./motion.cjs');
const {screens} = require('./screens.cjs');
const {mailboxFlow} = require('./mailbox-flow.cjs');
const {passkeyFlow} = require('./passkey-flow.cjs');
const {passkeyAccess} = require('./passkey-access.cjs');
const {accountReturn} = require('./account-return.cjs');
const {usability} = require('./usability.cjs');

async function main() {
  const mail = ownedMail(process.env.EASY_AUTH_MAILPIT_URL || 'http://127.0.0.1:8025', crypto.randomUUID());
  let browser, cleanup, failure, result;
  let external = 0, pageErrors = 0, cspViolations = 0;
  try {
    browser = await chromium.launch({headless: true});
    const versions = {chromium: browser.version(), node: process.version,
      playwright: require('../passkeys/node_modules/playwright/package.json').version, mailpit: await mail.version()};
    result = await withFixture(async origin => {
      const guard = async context => {
        await context.exposeBinding("recordUiViolation", () => { cspViolations += 1; });
        await context.addInitScript(() => document.addEventListener("securitypolicyviolation", () => window.recordUiViolation()));
        context.setDefaultTimeout(10000);
        context.setDefaultNavigationTimeout(10000);
        context.on('page', page => page.on('pageerror', () => { pageErrors += 1; }));
        await context.route('**/*', route => {
          if (new URL(route.request().url()).origin === origin) return route.continue();
          external += 1;
          return route.abort();
        });
      };
      const context = await browser.newContext();
      let appearance, focusedViews, animations;
      try {
        await guard(context);
        const page = await context.newPage();
        animations = await motion(page, origin);
        appearance = await presentation(page, origin);
        focusedViews = await screens(page, origin);
        await sharedLayout(page, origin);
      } finally { await context.close(); }
      const mailbox = await mailboxFlow(browser, origin, mail, guard);
      const passkeys = await passkeyFlow(browser, origin, mail, guard);
      const access = await passkeyAccess(browser, origin, mail, guard);
      const returned = await accountReturn(browser, origin, mail, guard);
      const controls = await usability(browser, origin, mail, guard);
      assert.equal(external, 0, 'no external browser requests');
      assert.equal(pageErrors, 0, 'no uncaught browser errors');
      assert.equal(cspViolations, 0, 'no CSP violations across genuine flows');
      return {versions, animations, appearance, focusedViews, mailbox, passkeys, access, returned, controls, external_requests: external, page_errors: pageErrors, csp_violations: cspViolations};
    });
    for (const [key, expected] of Object.entries({users: 5, credentials: 2, strong_verified_users: 1,
      signup_audits: 1, attachment_audits: 1, authentication_audits: 3,
      management_renames: 1, management_removals: 1, unproven_remaining_keys: 0,
      invalid_attachment_provenance: 0, attachment_pending: 0, signup_pending: 0})) {
      assert.equal(result.database[key], expected, 'committed UI database invariant: ' + key);
    }
  } catch (error) { failure = error; }
  finally {
    if (browser) await browser.close();
    try { cleanup = await mail.cleanup(); } catch { failure ||= new Error('owned mail cleanup'); }
  }
  if (failure) {
    // Never print assertion values, browser call logs, proof URLs or form data.
    const frame = (failure.stack || '').split('\n').find(line => /reference-ui\/[^ :]+\.cjs:\d+:\d+/.test(line));
    const source = frame?.match(/reference-ui\/[^ :]+\.cjs:\d+:\d+/)?.[0];
    console.error(JSON.stringify({passed: false, stage: failure.stageName || 'presentation-or-fixture',
      error: failure.name, source, observations: failure.uiObservations,
      fixture_cleanup_verified: failure.cleanupVerified === true || result?.fixture_database_removed === true, cleanup}));
    process.exitCode = 1;
  } else console.log(JSON.stringify({passed: true, ...result, cleanup}));
}
void main();
