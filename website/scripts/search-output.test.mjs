import test from "node:test";
import assert from "node:assert/strict";
import {
  mkdtemp,
  readFile,
  readdir,
  rm,
  stat,
  symlink,
  writeFile,
} from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { searchFixture } from "../tests/support/search.mjs";
import { verifyOutput, writeBundle } from "./search/output.mjs";

const files = await searchFixture();
async function owned(t) {
  const site = await mkdtemp(path.join(tmpdir(), "easy-auth-search-test-"));
  t.after(() => rm(site, { recursive: true, force: true }));
  return site;
}

test("all actual backend bytes are closed, read back and published together", async (t) => {
  const site = await owned(t);
  assert.equal(await writeBundle(site, files), files.length);
  await verifyOutput(path.join(site, "pagefind"), files);
  assert.deepEqual(await readdir(site), ["pagefind"]);
  for (const file of files) {
    assert.deepEqual(
      await readFile(path.join(site, "pagefind", file.path)),
      Buffer.from(file.content),
    );
  }
});

test("truncated, missing or unexpected disk output is rejected", async (t) => {
  const site = await owned(t);
  await writeBundle(site, files);
  const output = path.join(site, "pagefind");
  await writeFile(path.join(output, "pagefind.js"), "");
  await assert.rejects(verifyOutput(output, files), /Incomplete/);
  await writeFile(
    path.join(output, "pagefind.js"),
    files.find((f) => f.path === "pagefind.js").content,
  );
  for (const file of [
    files.find((f) => f.path === "pagefind.js"),
    files.find((f) => f.path.startsWith("index/")),
    files.find((f) => f.path.startsWith("fragment/")),
  ]) {
    await rm(path.join(output, file.path));
    await assert.rejects(verifyOutput(output, files), /Missing/);
    await writeFile(path.join(output, file.path), file.content);
  }
  await writeFile(path.join(output, "unexpected"), "unselected");
  await assert.rejects(verifyOutput(output, files), /Unexpected/);
});

test("invalid bundle cannot create an output or leave staging files", async (t) => {
  const site = await owned(t);
  await assert.rejects(writeBundle(site, []), /Missing/);
  assert.deepEqual(await readdir(site), []);
});

test("real write failure removes only its owned staging directory", async (t) => {
  const site = await owned(t);
  // File/directory conflict gives a real filesystem failure without mock writes.
  const conflict = [
    ...files,
    { path: "index", content: Buffer.from("owned conflict") },
  ];
  await assert.rejects(writeBundle(site, conflict), /EISDIR|EEXIST/);
  assert.deepEqual(await readdir(site), []);
});

test("existing bundle is preserved rather than completing a partial new build", async (t) => {
  const site = await owned(t);
  await writeBundle(site, files);
  await assert.rejects(writeBundle(site, files), /already exists/);
  await verifyOutput(path.join(site, "pagefind"), files);
});

test("a symlink cannot make external bytes count as generated output", async (t) => {
  const site = await owned(t);
  await writeBundle(site, files);
  const external = path.join(site, "owned-control");
  await writeFile(external, "owned control must not be read as an index");
  const target = path.join(site, "pagefind", "pagefind.js");
  await rm(target);
  await symlink(external, target);
  await assert.rejects(
    verifyOutput(path.join(site, "pagefind"), files),
    /Unexpected/,
  );
  assert.equal(
    await readFile(external, "utf8"),
    "owned control must not be read as an index",
  );
});

test("published static assets stay readable under a restrictive build umask", async (t) => {
  const site = await owned(t);
  const previous = process.umask(0o077);
  try {
    await writeBundle(site, files);
  } finally {
    process.umask(previous);
  }
  const output = path.join(site, "pagefind");
  assert.equal((await stat(output)).mode & 0o777, 0o755);
  for (const file of files) {
    assert.equal(
      (await stat(path.join(output, file.path))).mode & 0o777,
      0o644,
    );
    assert.equal(
      (await stat(path.dirname(path.join(output, file.path)))).mode & 0o777,
      0o755,
    );
  }
});
