import test from "node:test";
import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { pagefindVersion, validateBundle } from "./search/bundle.mjs";
import { searchFixture } from "../tests/support/search.mjs";

const files = await searchFixture();
const changed = (name, content) =>
  files.map((file) => (file.path === name ? { ...file, content } : file));

test("actual pinned Pagefind output validates without a live backend", async () => {
  const manifest = JSON.parse(
    await readFile(new URL("../package.json", import.meta.url), "utf8"),
  );
  assert.equal(manifest.devDependencies.pagefind, pagefindVersion);
  assert.equal(validateBundle(files).size, files.length);
});

test("empty, malformed and wrong-version entries cannot become successful output", () => {
  for (const content of [
    Buffer.alloc(0),
    Buffer.from("{"),
    Buffer.from("null"),
    Buffer.from('{"version":"wrong","languages":{}}'),
  ]) {
    assert.throws(() =>
      validateBundle(changed("pagefind-entry.json", content)),
    );
  }
});

test("all emitted assets must be nonempty including optional upstream assets", () => {
  for (const file of files) {
    assert.throws(
      () => validateBundle(changed(file.path, Buffer.alloc(0))),
      /Empty/,
    );
  }
});

test("critical entry references and index/fragment presence are required", () => {
  const entry = JSON.parse(
    Buffer.from(files.find((f) => f.path === "pagefind-entry.json").content),
  );
  const language = Object.values(entry.languages)[0];
  for (const name of [
    "pagefind.js",
    "pagefind-entry.json",
    "wasm.unknown.pagefind",
    `pagefind.${language.hash}.pf_meta`,
    `wasm.${language.wasm}.pagefind`,
  ]) {
    assert.throws(
      () => validateBundle(files.filter((f) => f.path !== name)),
      /Missing|Incomplete/,
    );
  }
  for (const prefix of ["index/", "fragment/"]) {
    assert.throws(
      () => validateBundle(files.filter((f) => !f.path.startsWith(prefix))),
      /Missing/,
    );
  }
});

test("truncated compressed assets and malformed text fail before writing", () => {
  const compressed = files.find((f) => f.path.endsWith(".pf_fragment"));
  assert.throws(() =>
    validateBundle(changed(compressed.path, compressed.content.slice(0, -1))),
  );
  assert.throws(() =>
    validateBundle(changed("pagefind.js", Buffer.from([255]))),
  );
});

test("duplicate and escaping paths cannot reach the filesystem", () => {
  assert.throws(() => validateBundle([...files, files[0]]), /Duplicate/);
  assert.throws(
    () =>
      validateBundle([
        ...files,
        { ...files[0], path: files[0].path.toUpperCase() },
      ]),
    /Duplicate/,
  );
  for (const path of [
    "../outside",
    "/outside",
    "a/../outside",
    "a\\outside",
    ".",
    "x//y",
  ]) {
    assert.throws(
      () => validateBundle([...files, { ...files[0], path }]),
      /Invalid search asset path/,
    );
  }
});
