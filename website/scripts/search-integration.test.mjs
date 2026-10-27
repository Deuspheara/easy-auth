import test from "node:test";
import assert from "node:assert/strict";
import { mkdtemp, readdir, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { pathToFileURL } from "node:url";
import starlight from "@astrojs/starlight";
import { buildSearch, verifiedSearch } from "./search/integration.mjs";

test("only the pinned Starlight writer hook is replaced", () => {
  const integration = starlight({ title: "Owned control" });
  const adapted = verifiedSearch(integration);
  assert.equal(adapted.name, integration.name);
  assert.deepEqual(Object.keys(adapted.hooks), Object.keys(integration.hooks));
  for (const [name, hook] of Object.entries(integration.hooks)) {
    assert.equal(
      adapted.hooks[name],
      name === "astro:build:done" ? buildSearch : hook,
    );
  }
  assert.notEqual(integration.hooks["astro:build:done"], buildSearch);
  assert.throws(
    () => verifiedSearch({ name: "unexpected", hooks: {} }),
    /Unexpected/,
  );
});

test("real empty index fails; later owned indexing still works after cleanup", async (t) => {
  const directory = await mkdtemp(
    path.join(tmpdir(), "easy-auth-search-hook-"),
  );
  t.after(() => rm(directory, { recursive: true, force: true }));
  const messages = [];
  const options = {
    dir: pathToFileURL(directory + path.sep),
    logger: { info: (message) => messages.push(message) },
  };
  await assert.rejects(buildSearch(options), /No search pages indexed/);
  assert.deepEqual(await readdir(directory), []);
  assert.deepEqual(messages, []);
  await writeFile(
    path.join(directory, "index.html"),
    '<html lang="en"><body data-pagefind-body>SAML control</body></html>',
  );
  await buildSearch(options);
  assert.equal(messages.length, 1);
  assert.match(messages[0], /Verified search index: 1 HTML files/);
  assert.ok(
    (await readdir(path.join(directory, "pagefind"))).includes(
      "pagefind-entry.json",
    ),
  );
});
