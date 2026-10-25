'use strict';
const assert = require('node:assert/strict');

function luminance(color) {
  if (/^okl(?:ab|ch)\(/.test(color)) {
    const values = color.match(/[-+]?(?:\d*\.)?\d+(?:e[-+]?\d+)?/gi).map(Number);
    const [L, x, y] = values;
    const angle = y * Math.PI / 180;
    const a = color.startsWith('oklch') ? x * Math.cos(angle) : x;
    const b = color.startsWith('oklch') ? x * Math.sin(angle) : y;
    const l = (L + .3963377774 * a + .2158037573 * b) ** 3;
    const m = (L - .1055613458 * a - .0638541728 * b) ** 3;
    const n = (L - .0894841775 * a - 1.291485548 * b) ** 3;
    // CSS Color 4 Oklab -> linear sRGB, then WCAG relative luminance.
    const rgb = [4.0767416621*l - 3.3077115913*m + .2309699292*n,
      -1.2684380046*l + 2.6097574011*m - .3413193965*n,
      -.0041960863*l - .7034186147*m + 1.707614701*n].map(v => Math.min(1, Math.max(0, v)));
    return .2126*rgb[0] + .7152*rgb[1] + .0722*rgb[2];
  }
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
  await page.waitForFunction(() => document.getElementById('clear-session').hidden === false);
  assert.equal(await page.locator('html').getAttribute('data-theme'), null, 'fresh theme follows the OS');
  assert.equal(await page.evaluate(async () => {
    await document.fonts.ready;
    return [...document.fonts].some(font => font.family === 'Inter' && font.status === 'loaded');
  }), true, 'bundled local Inter is loaded');
  await page.keyboard.press('Tab');
  assert.equal(await page.getByRole('link', {name: 'Skip to account access'}).evaluate(node => node === document.activeElement), true);
  assert.equal(await page.getByRole('link', {name: 'Skip to account access'}).evaluate(node => getComputedStyle(node).outlineStyle), 'solid');
  await page.keyboard.press('Enter');
  assert.equal(await page.locator('#main').evaluate(node => node === document.activeElement), true);
  await page.locator('#email').focus();
  const results = [];
  for (const scheme of ['light', 'dark']) {
    await page.emulateMedia({colorScheme: scheme});
    await page.waitForFunction(dark => document.getElementById('theme').getAttribute('aria-label') === (dark ? 'Use light theme' : 'Use dark theme'), scheme === 'dark');
    // Vega transitions control colors during theme changes; measure the settled theme.
    await page.evaluate(() => Promise.all(document.getAnimations().map(animation => animation.finished.catch(() => {}))));
    for (const width of [320, 390, 768, 1024, 1280, 1440]) {
      await page.setViewportSize({width, height: 1000});
      assert.equal(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth), true, 'document reflow');
      const colors = await page.evaluate(() => {
        const style = node => getComputedStyle(node);
        const surface = node => {
          const ancestors = [];
          for (let current = node; current; current = current.parentElement) ancestors.unshift(current);
          const canvas = document.createElement('canvas'); canvas.width = canvas.height = 1;
          const context = canvas.getContext('2d'); context.fillStyle = 'white'; context.fillRect(0, 0, 1, 1);
          for (const ancestor of ancestors) { context.fillStyle = style(ancestor).backgroundColor; context.fillRect(0, 0, 1, 1); }
          const [r, g, b] = context.getImageData(0, 0, 1, 1).data;
          return `rgb(${r}, ${g}, ${b})`;
        };
        return {
          ink: style(document.body).color, page: style(document.body).backgroundColor,
          muted: style(document.querySelector('#intro')).color,
          surface: surface(document.querySelector('#email')),
          inputText: style(document.querySelector('#email')).color,
          button: style(document.querySelector('#submit')).color,
          accent: surface(document.querySelector('#submit')),
          border: style(document.querySelector('#email')).borderColor
        };
      });
      assert.equal(contrast(colors.ink, colors.page) >= 4.5, true, 'body contrast');
      assert.equal(contrast(colors.muted, colors.page) >= 4.5, true, 'secondary text contrast');
      assert.equal(contrast(colors.button, colors.accent) >= 4.5, true, 'button contrast');
      assert.equal(contrast(colors.border, colors.surface) >= 3, true, 'input boundary contrast');
      assert.equal(contrast(colors.inputText, colors.surface) >= 4.5, true, 'input text contrast');
      results.push({scheme, width, reflow: true, contrast: true});
      if (width === 320 && process.env.EASY_AUTH_UI_SCREENSHOT_DIR) {
        const path = require('node:path');
        await page.screenshot({animations: 'disabled', path: path.join(process.env.EASY_AUTH_UI_SCREENSHOT_DIR, scheme + '-320.png'), fullPage: true});
      }
    }
    await page.setViewportSize({width: 320, height: 844});
    await page.evaluate(() => { document.documentElement.style.fontSize = '200%'; });
    assert.equal(await page.locator('#heading').evaluate(node => getComputedStyle(node).fontSize), '52px');
    assert.equal(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth), true, '200 percent text reflow');
    if (process.env.EASY_AUTH_UI_SCREENSHOT_DIR) {
      const path = require('node:path');
      await page.screenshot({animations: 'disabled', path: path.join(process.env.EASY_AUTH_UI_SCREENSHOT_DIR, scheme + '-320-text200.png'), fullPage: true});
    }
    await page.evaluate(() => { document.documentElement.style.removeProperty('font-size'); });
    await page.setViewportSize({width: 1440, height: 1000});
    if (process.env.EASY_AUTH_UI_SCREENSHOT_DIR) {
      const path = require('node:path');
      await page.screenshot({animations: 'disabled', path: path.join(process.env.EASY_AUTH_UI_SCREENSHOT_DIR, scheme + '.png'), fullPage: true});
    }
  }
  await page.emulateMedia({reducedMotion: 'reduce'});
  assert.equal(await page.evaluate(() => getComputedStyle(document.body, '::before').animationName), 'none');
  await page.emulateMedia({reducedMotion: 'no-preference'});
  assert.equal(await page.evaluate(() => getComputedStyle(document.body, '::before').animationName), 'none');
  await page.emulateMedia({forcedColors: 'active'});
  assert.equal(await page.locator('#email').evaluate(node => getComputedStyle(node).borderStyle), 'solid');
  await page.emulateMedia({forcedColors: 'none', colorScheme: 'light'});
  await page.setViewportSize({width: 1280, height: 1000});
  return results;
}
module.exports = {presentation, contrast};
