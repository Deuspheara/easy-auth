import assert from "node:assert/strict";

export async function checkInteractions(page, origin) {
  await page.goto(origin + "/");
  await page.getByRole("tab", { name: "Run the service" }).click();
  assert.equal(await page.locator("#panel-standalone").isVisible(), true);
  await page.getByRole("button", { name: "Copy example" }).click();
  assert.match(
    await page.evaluate(() => navigator.clipboard.readText()),
    /cargo run -p easy-auth-server/,
  );
  await page.getByRole("tab", { name: "Run the service" }).press("ArrowLeft");
  assert.equal(await page.locator("#panel-embedded").isVisible(), true);
  await page.screenshot({
    path: "/tmp/easy-auth-website-desktop.png",
    fullPage: true,
  });
  await page.getByRole("button", { name: "Toggle color theme" }).click();
  assert.equal(await page.locator("html").getAttribute("data-theme"), "light");
  await page.reload();
  assert.equal(await page.locator("html").getAttribute("data-theme"), "light");
  await page.screenshot({
    path: "/tmp/easy-auth-website-light.png",
    fullPage: true,
  });
}

export async function checkMobileAndSearch(page, origin) {
  await page.setViewportSize({ width: 390, height: 844 });
  await page.getByRole("button", { name: "Open navigation" }).click();
  assert.equal(await page.locator("#site-navigation").isVisible(), true);
  await page.keyboard.press("Escape");
  assert.equal(await page.locator("#site-navigation").isVisible(), false);
  await page.screenshot({
    path: "/tmp/easy-auth-website-mobile.png",
    fullPage: true,
  });
  assert.ok(
    await page.evaluate(
      () => document.documentElement.scrollWidth <= innerWidth,
    ),
    "Landing must fit mobile",
  );
  await page.goto(origin + "/docs/");
  await page.getByRole("button", { name: /search/i }).click();
  await page.locator("dialog input").fill("SAML");
  await page.locator(".pagefind-ui__result-link").first().waitFor();
  assert.ok(
    (await page.locator(".pagefind-ui__result-link").count()) > 0,
    "Search must return indexed guides",
  );
  await page.keyboard.press("Escape");
}

export async function checkRoutes(page, origin) {
  const queue = ["/"];
  const visited = new Set();
  const anchors = [];
  while (queue.length) {
    const route = queue.shift();
    if (visited.has(route)) continue;
    visited.add(route);
    const response = await page.goto(origin + route);
    assert.equal(response.status(), 200, `Route ${route}`);
    assert.ok(
      await page.evaluate(
        () => document.documentElement.scrollWidth <= innerWidth,
      ),
      `Mobile width: ${route}`,
    );
    const links = await page
      .locator("a[href]")
      .evaluateAll((nodes) => nodes.map((n) => n.href));
    for (const href of links) {
      const target = new URL(href);
      if (
        target.origin !== new URL(origin).origin ||
        !target.pathname.endsWith("/")
      )
        continue;
      const routePath =
        target.pathname.slice(new URL(origin).pathname.length) || "/";
      assert.ok(
        target.pathname.startsWith(new URL(origin).pathname + "/"),
        `Link escaped project base: ${href}`,
      );
      if (!visited.has(routePath)) queue.push(routePath);
      if (target.hash)
        anchors.push({
          from: route,
          path: routePath,
          hash: decodeURIComponent(target.hash.slice(1)),
        });
    }
  }
  for (const anchor of anchors) {
    await page.goto(origin + anchor.path);
    assert.ok(
      await page.evaluate((id) => !!document.getElementById(id), anchor.hash),
      `Missing anchor ${anchor.path}#${anchor.hash} from ${anchor.from}`,
    );
  }
  return { routes: visited.size, anchors: anchors.length };
}
