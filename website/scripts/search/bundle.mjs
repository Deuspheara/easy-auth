import { gunzipSync } from "node:zlib";

export const pagefindVersion = "1.5.2";
const compressed = /\.(?:pagefind|pf_meta|pf_index|pf_fragment|pf_filter)$/;
const marker = Buffer.from("pagefind_dcd");

export function assetPath(value) {
  if (
    typeof value !== "string" ||
    !/^[a-zA-Z0-9_.-]+(?:\/[a-zA-Z0-9_.-]+)*$/.test(value) ||
    value.split("/").some((part) => part === "." || part === "..")
  ) {
    throw new Error("Invalid search asset path");
  }
  return value;
}

// Pagefind's complete in-memory response is the expected bundle. Validate it
// before touching output; Node then owns all writes independently of its backend.
export function validateBundle(files) {
  if (!Array.isArray(files) || files.length === 0) {
    throw new Error("Missing search assets");
  }
  const paths = new Set();
  const assets = new Map();
  for (const file of files) {
    const name = assetPath(file.path);
    if (paths.has(name.toLowerCase()))
      throw new Error("Duplicate search asset");
    paths.add(name.toLowerCase());
    if (!(file.content instanceof Uint8Array) || file.content.length === 0) {
      throw new Error("Empty or invalid search asset");
    }
    const content = Buffer.from(file.content);
    if (compressed.test(name)) {
      const decoded = gunzipSync(content);
      if (
        !decoded.subarray(0, marker.length).equals(marker) ||
        decoded.length <= marker.length
      ) {
        throw new Error("Invalid compressed search asset");
      }
    } else if (/\.(?:js|css|json)$/.test(name)) {
      if (!new TextDecoder("utf-8", { fatal: true }).decode(content).trim()) {
        throw new Error("Blank search asset");
      }
    }
    assets.set(name, content);
  }
  validateEntry(assets);
  if (
    !files.some((file) => file.path.startsWith("index/")) ||
    !files.some((file) => file.path.startsWith("fragment/"))
  ) {
    throw new Error("Missing search index or fragments");
  }
  return assets;
}

function validateEntry(assets) {
  for (const name of [
    "pagefind.js",
    "pagefind-entry.json",
    "wasm.unknown.pagefind",
  ]) {
    if (!assets.has(name)) throw new Error("Missing critical search asset");
  }
  const entry = JSON.parse(assets.get("pagefind-entry.json").toString("utf8"));
  if (
    entry?.version !== pagefindVersion ||
    typeof entry.languages !== "object" ||
    !entry.languages ||
    Array.isArray(entry.languages) ||
    Object.keys(entry.languages).length === 0
  ) {
    throw new Error("Invalid search index entry");
  }
  for (const language of Object.values(entry.languages)) {
    if (
      !language ||
      typeof language !== "object" ||
      !Number.isSafeInteger(language.page_count) ||
      language.page_count <= 0 ||
      !assets.has(`pagefind.${language.hash}.pf_meta`) ||
      !assets.has(`wasm.${language.wasm}.pagefind`)
    ) {
      throw new Error("Incomplete search language assets");
    }
  }
}
