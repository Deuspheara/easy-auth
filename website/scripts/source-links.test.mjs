import test from "node:test";
import assert from "node:assert/strict";
import { rewriteTree } from "./source-links.mjs";
import { guides } from "./docs-manifest.mjs";
import { git, revision } from "./public-docs.mjs";

const source = "docs/guides/saml.md";
const link = (url) => ({
  type: "link",
  url,
  children: [{ type: "text", value: "reference" }],
});

test("selected committed guides remain local with their anchors", () => {
  const node = link("sessions.md#session-management");
  rewriteTree(node, source, new Set(["docs/guides/sessions.md"]));
  assert.equal(node.url, "/docs/guides/sessions/#session-management");
});

test("unselected committed references bind to the exact source revision", () => {
  const node = link("../architecture/overview.md");
  rewriteTree(node, source, new Set(["docs/architecture/overview.md"]));
  assert.equal(
    node.url,
    `https://github.com/Deuspheara/easy-auth/blob/${revision}/docs/architecture/overview.md`,
  );
});

test("private and uncommitted references never become published links", () => {
  const tree = {
    type: "root",
    children: [
      link("../security/private-review.md"),
      { type: "image", url: "../security/private.png", alt: "diagram" },
    ],
  };
  rewriteTree(tree, source, new Set());
  assert.deepEqual(tree.children, [
    { type: "text", value: "reference" },
    { type: "text", value: "diagram" },
  ]);
  assert.throws(
    () =>
      rewriteTree(
        { type: "definition", url: "../security/private.md" },
        source,
        new Set(),
      ),
    /unpublished/,
  );
});

test("code and external URLs are preserved literally", () => {
  const tree = {
    type: "root",
    children: [
      { type: "code", value: "[private](../security/private.md)" },
      link("https://example.org/guide"),
      link("#existing"),
    ],
  };
  const original = structuredClone(tree);
  rewriteTree(tree, source, new Set());
  assert.deepEqual(tree, original);
});

test("public source allowlist contains only distinct committed regular guides", () => {
  assert.equal(new Set(guides.map((g) => g.slug)).size, guides.length);
  for (const guide of guides) {
    assert.match(guide.source, /^docs\/guides\/[a-z-]+\.md$/);
    assert.match(git("ls-tree", revision, "--", guide.source), /^100644 blob /);
  }
});
