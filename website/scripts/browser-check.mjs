import assert from "node:assert/strict";
import {
  checkInteractions,
  checkMobileAndSearch,
  checkRoutes,
} from "./browser-scenarios.mjs";
import { base } from "./site-path.mjs";
import { preview } from "astro";
import { chromium } from "playwright";

// Use the programmatic API so this check owns and closes the exact server.
const server = await preview({ server: { host: "127.0.0.1", port: 0 } });
const origin = `http://127.0.0.1:${server.port}${base}`;
let browser;
try {
  browser = await chromium.launch({ headless: true });
  const context = await browser.newContext({
    viewport: { width: 1440, height: 1000 },
    colorScheme: "dark",
    permissions: ["clipboard-read", "clipboard-write"],
  });
  const page = await context.newPage();
  const errors = [];
  page.on("pageerror", (error) => errors.push(error.message));
  page.on("response", (response) => {
    if (response.url().startsWith(origin + "/") && response.status() >= 400) {
      errors.push(
        `HTTP ${response.status()} ${new URL(response.url()).pathname}`,
      );
    }
  });
  await checkInteractions(page, origin);
  await checkMobileAndSearch(page, origin);
  const counts = await checkRoutes(page, origin);
  assert.deepEqual(errors, [], "No browser runtime errors");
  console.log(
    `Browser checks passed: interactions, search, mobile layout, ${counts.routes} routes, ${counts.anchors} anchors.`,
  );
} finally {
  await browser?.close();
  await server.stop();
}
