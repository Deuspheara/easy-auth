import { createHash } from "node:crypto";
import { mkdirSync, rmSync, writeFileSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { guides } from "./docs-manifest.mjs";
import { git, revision, website } from "./public-docs.mjs";

export function syncDocs() {
  const destination = path.join(website, "src/content/docs/docs/guides");
  rmSync(destination, { recursive: true, force: true });
  mkdirSync(destination, { recursive: true });
  const sources = guides.map((guide, index) => {
    if (!/^docs\/guides\/[a-z-]+\.md$/.test(guide.source))
      throw new Error("Non-public guide path");
    if (
      !git("ls-tree", revision, "--", guide.source).startsWith("100644 blob ")
    ) {
      throw new Error("Guide must be a committed regular Markdown file");
    }
    const original = git("show", `${revision}:${guide.source}`);
    const body = original.replace(/^# .+\n/, "");
    const frontmatter = `---\ntitle: ${JSON.stringify(guide.title)}\ndescription: ${JSON.stringify(guide.title + " — easy-auth public reference guide.")}\nsidebar:\n  order: ${index + 1}\neditUrl: false\n---\n\n`;
    const source = `> Published from the [repository guide](https://github.com/Deuspheara/easy-auth/blob/${revision}/${guide.source}). See [Feature status](/docs/features/) for current availability.\n\n`;
    writeFileSync(
      path.join(destination, guide.slug + ".md"),
      frontmatter + source + body,
    );
    return {
      path: guide.source,
      sha256: createHash("sha256").update(original).digest("hex"),
    };
  });
  mkdirSync(path.join(website, "public"), { recursive: true });
  writeFileSync(
    path.join(website, "public/docs-provenance.json"),
    JSON.stringify({ revision, sources }, null, 2) + "\n",
  );
  console.log(
    `Published ${sources.length} allowlisted committed guides from ${revision.slice(0, 7)}.`,
  );
}
if (process.argv[1] === fileURLToPath(import.meta.url)) syncDocs();
