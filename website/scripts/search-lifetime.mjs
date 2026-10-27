// Bounded independent diagnostic samples, never retries for a failed site build.
import * as pagefind from "pagefind";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { writeBundle, verifyOutput } from "./search/output.mjs";

const runs = 12;
const directory = await mkdtemp(
  path.join(tmpdir(), "easy-auth-search-lifetime-"),
);
const results = [];
try {
  for (const mode of ["upstream", "verified"]) {
    for (let run = 0; run < runs; run++) {
      try {
        const created = await pagefind.createIndex();
        if (created.errors.length)
          throw new Error("Diagnostic index creation failed");
        const added = await created.index.addHTMLFile({
          url: "/docs/",
          content:
            '<html lang="en"><head><title>Owned search control</title></head><body data-pagefind-body><h1>SAML recovery</h1><p>Scoped owned documentation search fixture.</p></body></html>',
        });
        if (added.errors.length) throw new Error("Diagnostic indexing failed");
        const expected = await created.index.getFiles();
        if (expected.errors.length)
          throw new Error("Diagnostic file response failed");
        const site = await mkdtemp(path.join(directory, mode + "-"));
        if (mode === "upstream") {
          const written = await created.index.writeFiles({
            outputPath: path.join(site, "pagefind"),
          });
          if (written.errors.length)
            throw new Error("Diagnostic upstream write failed");
          await pagefind.close();
        } else {
          await pagefind.close();
          await writeBundle(site, expected.files);
        }
        try {
          await verifyOutput(path.join(site, "pagefind"), expected.files);
          results.push({ mode, run, complete: true });
        } catch (error) {
          results.push({ mode, run, complete: false, reason: error.message });
        }
      } finally {
        await pagefind.close();
      }
    }
  }
} finally {
  await rm(directory, { recursive: true, force: true });
}
for (const mode of ["upstream", "verified"]) {
  const selected = results.filter((result) => result.mode === mode);
  console.log(
    JSON.stringify({
      mode,
      runs: selected.length,
      incomplete: selected.filter((result) => !result.complete).length,
    }),
  );
}
if (results.some((result) => result.mode === "verified" && !result.complete)) {
  throw new Error("Verified writer produced incomplete output");
}
