import test from "node:test";
import assert from "node:assert/strict";
import { sitePath, baseLinks } from "./site-path.mjs";

test("project-site URLs stay under the repository base exactly once", () => {
  assert.equal(sitePath("/"), "/easy-auth/");
  assert.equal(
    sitePath("/docs/#configuration"),
    "/easy-auth/docs/#configuration",
  );
  assert.equal(sitePath("/easy-auth/docs/"), "/easy-auth/docs/");
  for (const url of [
    "#section",
    "https://example.com/",
    "//example.com/",
    "relative.md",
  ]) {
    assert.equal(sitePath(url), url);
  }
});

test("Markdown base rewriting preserves literal code and external destinations", () => {
  const tree = {
    type: "root",
    children: [
      { type: "link", url: "/docs/", children: [] },
      { type: "code", value: 'fetch("/v1/session")' },
      { type: "link", url: "https://example.com/", children: [] },
    ],
  };
  baseLinks()(tree);
  assert.equal(tree.children[0].url, "/easy-auth/docs/");
  assert.equal(tree.children[1].value, 'fetch("/v1/session")');
  assert.equal(tree.children[2].url, "https://example.com/");
});
