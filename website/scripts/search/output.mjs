import {
  mkdir,
  mkdtemp,
  readFile,
  readdir,
  rename,
  rm,
  writeFile,
} from "node:fs/promises";
import path from "node:path";
import { assetPath, validateBundle } from "./bundle.mjs";

async function checkDirectory(directory, assets, prefix = "") {
  const found = new Set();
  for (const entry of await readdir(path.join(directory, prefix), {
    withFileTypes: true,
  })) {
    const name = prefix + entry.name;
    if (entry.isDirectory()) {
      if (![...assets.keys()].some((file) => file.startsWith(name + "/"))) {
        throw new Error("Unexpected search output directory");
      }
      const nested = await checkDirectory(directory, assets, name + "/");
      for (const file of nested) found.add(file);
    } else {
      if (!entry.isFile() || !assets.has(name))
        throw new Error("Unexpected search output");
      const actual = await readFile(path.join(directory, name));
      if (!actual.equals(assets.get(name)))
        throw new Error("Incomplete search output");
      found.add(name);
    }
  }
  return found;
}

export async function verifyOutput(directory, files) {
  const assets = validateBundle(files);
  const found = await checkDirectory(directory, assets);
  if (found.size !== assets.size) throw new Error("Missing search output");
}

export async function writeBundle(site, files) {
  const assets = validateBundle(files);
  const destination = path.join(site, "pagefind");
  // Astro creates a fresh output directory. Refuse preexisting output so stale
  // hashed fragments cannot silently complete a partial new index.
  const entries = await readdir(site);
  if (entries.includes("pagefind"))
    throw new Error("Search output already exists");
  const staging = await mkdtemp(path.join(site, ".pagefind-"));
  try {
    for (const [name, content] of assets) {
      const target = path.join(staging, assetPath(name));
      await mkdir(path.dirname(target), { recursive: true });
      // Await the Node-owned file close, not a response from a killed writer.
      await writeFile(target, content, { flag: "wx" });
    }
    await verifyOutput(staging, files);
    await rename(staging, destination);
  } finally {
    await rm(staging, { recursive: true, force: true });
  }
  return assets.size;
}
