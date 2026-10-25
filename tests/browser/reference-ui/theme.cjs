'use strict';

async function selectTheme(page, scheme) {
  await page.emulateMedia({colorScheme: scheme});
  await page.waitForFunction(dark => document.getElementById('theme').getAttribute('aria-label') === (dark ? 'Use light theme' : 'Use dark theme'), scheme === 'dark');
  // Vega transitions control colors during theme changes; measure the settled theme.
  await page.evaluate(() => Promise.all(document.getAnimations().map(animation => animation.finished.catch(() => {}))));
}

module.exports = {selectTheme};
