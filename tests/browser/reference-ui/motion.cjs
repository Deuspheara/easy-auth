'use strict';
const assert = require('node:assert/strict');

// Presentation probes use the real Axum document/CSP, never authentication mocks.
async function motion(page, origin) {
  await page.goto(origin);
  await page.waitForFunction(() => !document.getElementById('clear-session').hidden);
  await page.evaluate(async () => {
    const module = await import('/ui/presentation-motion.js');
    await import('/ui/motion.js');
    window.motionProbe = module;
    window.uiViolations = [];
    document.addEventListener('securitypolicyviolation', event => window.uiViolations.push(event.effectiveDirective));
  });
  const start = () => page.evaluate(() => window.motionProbe.present(document.querySelector('[data-auth-screen="email"]')));
  const clean = async () => {
    assert.equal(await page.evaluate(() => {
      const node = document.querySelector('[data-auth-screen="email"]');
      return node.style.opacity === '' && node.style.transform === '' && node.getAnimations().length === 0 && getComputedStyle(node).opacity === '1';
    }), true, 'animation releases only its owned styles and handles');
    assert.deepEqual(await page.evaluate(() => window.uiViolations), [], 'enforced CSP');
  };
  await start();
  assert.equal(await page.evaluate(() => document.querySelector('[data-auth-screen="email"]').getAnimations().length > 0), true);
  await page.waitForTimeout(220);
  await clean();
  await start();
  await page.evaluate(() => window.motionProbe.cancelPresentation());
  await clean();
  await start(); await start(); await start();
  await page.waitForTimeout(220);
  await clean();
  await start();
  await page.emulateMedia({reducedMotion: 'reduce'});
  await page.waitForTimeout(50);
  await clean(); await start(); await clean();
  await page.emulateMedia({reducedMotion: 'no-preference', forcedColors: 'active'});
  await start(); await clean();
  await page.emulateMedia({forcedColors: 'none'});
  await page.evaluate(() => {
    const node = document.createElement('div');
    document.querySelector('main').append(node);
    window.motionProbe.present(node);
    window.motionProbe.cancelPresentation();
    node.remove();
  });
  assert.deepEqual(await page.evaluate(() => window.uiViolations), []);
  await page.route('**/ui/motion.js', route => route.abort());
  await page.goto(origin);
  await page.waitForFunction(() => !document.getElementById('clear-session').hidden);
  await page.locator('#theme').click();
  await page.getByRole('link', {name: 'Use a password instead'}).click();
  await page.locator('#password-form').waitFor({state: 'visible'});
  assert.equal(await page.locator('#password-form').isVisible(), true, 'missing Motion preserves initialization/navigation');
  await page.unroute('**/ui/motion.js');
  await page.route('**/ui/presentation-motion.js', route => route.abort());
  await page.goto(origin);
  await page.waitForFunction(() => !document.getElementById('clear-session').hidden);
  await page.getByRole('link', {name: 'Use a password instead'}).click();
  await page.locator('#password-form').waitFor({state: 'visible'});
  await page.unroute('**/ui/presentation-motion.js');
  return {completion: true, cancellation: true, replacement: true, removal: true, reduced: true, forced: true, unavailable: true, adapter_unavailable: true, csp: true};
}
module.exports = {motion};
