import path from "node:path";
import { guides } from "./docs-manifest.mjs";
import { published, revision } from "./public-docs.mjs";

const routes = new Map(
  guides.map((g) => [g.source, `/docs/guides/${g.slug}/`]),
);

// Work on the renderer's Markdown AST: code samples are never rewritten.
export function rewriteTree(node, source, files = published) {
  if (
    ["link", "image", "definition"].includes(node.type) &&
    node.url &&
    !/^(https?:|mailto:|#|\/)/.test(node.url)
  ) {
    const [file, fragment] = node.url.split("#");
    const resolved = path.posix.normalize(
      path.posix.join(path.posix.dirname(source), file),
    );
    if (!files.has(resolved)) {
      if (node.type === "link") return node.children ?? [];
      if (node.type === "image")
        return [{ type: "text", value: node.alt ?? "" }];
      throw new Error("A reference definition points to an unpublished source");
    }
    const remote =
      node.type === "image"
        ? `https://raw.githubusercontent.com/Deuspheara/easy-auth/${revision}/${resolved}`
        : `https://github.com/Deuspheara/easy-auth/blob/${revision}/${resolved}`;
    node.url =
      (routes.get(resolved) ?? remote) + (fragment ? `#${fragment}` : "");
  }
  if (node.children)
    node.children = node.children.flatMap((child) =>
      rewriteTree(child, source, files),
    );
  return [node];
}

export default function sourceLinks() {
  return (tree, file) => {
    const location = String(file.path).replaceAll("\\", "/");
    if (!location.includes("/content/docs/docs/guides/")) return;
    const guide = guides.find((g) => location.endsWith("/" + g.slug + ".md"));
    if (!guide) throw new Error("Unlisted generated guide");
    rewriteTree(tree, guide.source);
  };
}
