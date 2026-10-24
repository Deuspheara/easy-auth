'use strict';
const assert = require('node:assert/strict');

function luminance(color) {
  const rgb = color.match(/[\d.]+/g).slice(0, 3).map(Number).map(value => {
    value /= 255;
    return value <= .04045 ? value / 12.92 : ((value + .055) / 1.055) ** 2.4;
  });
  return rgb[0] * .2126 + rgb[1] * .7152 + rgb[2] * .0722;
}
function contrast(a, b) {
  const x = luminance(a), y = luminance(b);
  return (Math.max(x, y) + .05) / (Math.min(x, y) + .05);
}
async function presentation(page, origin) {
  await page.goto(origin);
  await page.locator('#clear-session').waitFor({state: 'visible'});
  await page.keyboard.press('Tab');
  assert.equal(await page.getByRole('link', {name: 'Skip to account access'}).evaluate(node => node === document.activeElement), true);
  assert.equal(await page.getByRole('link', {name: 'Skip to account access'}).evaluate(node => getComputedStyle(node).outlineStyle), 'solid');
  await page.keyboard.press('Enter');
  assert.equal(await page.locator('#main').evaluate(node => node === document.activeElement), true);
  const results = [];
  for (const scheme of ['light', 'dark']) {
    await page.emulateMedia({colorScheme: scheme});
    await page.waitForFunction(dark => document.getElementById('theme').textContent === (dark ? 'Use light theme' : 'Use dark theme'), scheme === 'dark');
    for (const width of [320, 768, 1440]) {
      await page.setViewportSize({width, height: 1000});
      assert.equal(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth), true, 'document reflow');
      const colors = await page.evaluate(() => {
        const style = node => getComputedStyle(node);
        return {
          ink: style(document.body).color, page: style(document.body).backgroundColor,
          muted: style(document.querySelector('.card .muted')).color,
          surface: style(document.querySelector('.card')).backgroundColor,
          button: style(document.querySelector('#submit')).color,
          accent: style(document.querySelector('#submit')).backgroundColor,
          border: style(document.querySelector('#email')).borderColor
        };
      });
      assert.equal(contrast(colors.ink, colors.page) >= 4.5, true, 'body contrast');
      assert.equal(contrast(colors.muted, colors.surface) >= 4.5, true, 'secondary text contrast');
      assert.equal(contrast(colors.button, colors.accent) >= 4.5, true, 'button contrast');
      assert.equal(contrast(colors.border, colors.surface) >= 3, true, 'input boundary contrast');
      results.push({scheme, width, reflow: true, contrast: true});
      if (width === 320 && process.env.EASY_AUTH_UI_SCREENSHOT_DIR) {
        const path = require('node:path');
        await page.screenshot({path: path.join(process.env.EASY_AUTH_UI_SCREENSHOT_DIR, scheme + '-320.png'), fullPage: true});
      }
    }
    if (process.env.EASY_AUTH_UI_SCREENSHOT_DIR) {
      const path = require('node:path');
      await page.screenshot({path: path.join(process.env.EASY_AUTH_UI_SCREENSHOT_DIR, scheme + '.png'), fullPage: true});
    }
  }
  await page.emulateMedia({forcedColors: 'active'});
  assert.equal(await page.locator('#email').evaluate(node => getComputedStyle(node).borderStyle), 'solid');
  await page.emulateMedia({forcedColors: 'none', colorScheme: 'light'});
  await page.setViewportSize({width: 1280, height: 1000});
  return results;
}
module.exports = {presentation};
