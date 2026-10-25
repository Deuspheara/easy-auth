'use strict';
const path = require('node:path');
const captured = new Set();

// Optional local review evidence. Never persist passwords, recovery codes or proof URLs.
async function captureScreen(page, name) {
  const directory = process.env.EASY_AUTH_UI_SCREENSHOT_DIR;
  if (!directory || captured.has(name)) return;
  await page.waitForFunction(() => !document.querySelector('[aria-busy="true"]') || document.querySelector('dialog[open]'));
  await page.evaluate(() => document.fonts.ready);
  const viewport = page.viewportSize();
  const dark = await page.evaluate(() => matchMedia('(prefers-color-scheme: dark)').matches);
  const mask = [];
  for (const field of await page.locator('input[type="password"], #saved-code').all()) {
    if (await field.inputValue()) mask.push(field);
  }
  try {
    for (const scheme of ['light', 'dark']) {
      await page.emulateMedia({colorScheme: scheme});
      for (const width of [320, 1440]) {
        await page.setViewportSize({width, height: 1000});
        await page.screenshot({path: path.join(directory, `${name}-${scheme}-${width}.png`),
          animations: 'disabled', fullPage: true, mask, maskColor: '#64748b'});
      }
    }
    captured.add(name);
  } finally {
    await page.emulateMedia({colorScheme: dark ? 'dark' : 'light'});
    if (viewport) await page.setViewportSize(viewport);
  }
}
module.exports = {captureScreen};
