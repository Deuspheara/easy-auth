import { defineConfig } from "astro/config";
import { unified } from "@astrojs/markdown-remark";
import starlight from "@astrojs/starlight";
import { site, base, baseLinks } from "./scripts/site-path.mjs";
import sourceLinks from "./scripts/source-links.mjs";

export default defineConfig({
  output: "static",
  site,
  base,
  trailingSlash: "always",
  markdown: { processor: unified({ remarkPlugins: [sourceLinks, baseLinks] }) },
  integrations: [
    starlight({
      title: "easy-auth",
      disable404Route: true,
      description:
        "Rust-first authentication. Embed in Axum or run the same core as a service.",
      logo: { src: "./public/logo.svg" },
      favicon: "/favicon.svg",
      social: [
        {
          icon: "github",
          label: "GitHub",
          href: "https://github.com/Deuspheara/easy-auth",
        },
      ],
      customCss: ["./src/styles/docs.css"],
      sidebar: [
        {
          label: "Get started",
          items: [
            { label: "Introduction", slug: "docs" },
            { label: "Quickstart", slug: "docs/getting-started" },
            { label: "Protect an Axum route", slug: "docs/embedding" },
            { label: "Browser integration", slug: "docs/browser-integration" },
            { label: "Use in your project", slug: "docs/your-project" },
            { label: "Feature status", slug: "docs/features" },
          ],
        },
        {
          label: "Authentication",
          items: [{ autogenerate: { directory: "docs/guides" } }],
        },
        {
          label: "Understand & deploy",
          items: [
            { label: "Users, realms & sessions", slug: "docs/concepts" },
            { label: "Deployment checklist", slug: "docs/deployment" },
            { label: "Troubleshooting", slug: "docs/troubleshooting" },
          ],
        },
      ],
    }),
  ],
});
