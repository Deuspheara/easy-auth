// The repository is published as a GitHub Pages project site, not a user site.
export const site = "https://deuspheara.github.io";
export const base = "/easy-auth";
export function sitePath(url) {
  if (!url.startsWith("/") || url.startsWith("//")) return url;
  if (url === base || url.startsWith(base + "/")) return url;
  return base + url;
}

// Rewrite Markdown links through the AST, leaving examples and external URLs intact.
export function baseLinks() {
  return function visit(node) {
    if (["link", "image", "definition"].includes(node.type) && node.url) {
      node.url = sitePath(node.url);
    }
    node.children?.forEach(visit);
  };
}
