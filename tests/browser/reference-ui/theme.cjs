'use strict';

async function selectTheme(page, scheme) {
  await page.emulateMedia({colorScheme: scheme});
  await page.waitForFunction(dark => document.getElementById('theme').getAttribute('aria-label') === (dark ? 'Use light theme' : 'Use dark theme'), scheme === 'dark');
  // Vega transitions control colors during theme changes; measure the settled theme.
  await page.evaluate(() => Promise.all(document.getAnimations().map(animation => animation.finished.catch(() => {}))));
  // Inherited color changes can start child transitions after the first batch ends.
  await page.waitForFunction(() => document.getAnimations().every(animation => animation.playState !== 'running' && !animation.pending));
}

module.exports = {selectTheme};
