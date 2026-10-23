import { defineConfig } from "astro/config";
import { unified } from "@astrojs/markdown-remark";
import starlight from "@astrojs/starlight";
import sourceLinks from "./scripts/source-links.mjs";

export default defineConfig({
  output: "static",
  trailingSlash: "always",
  markdown: { processor: unified({ remarkPlugins: [sourceLinks] }) },
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
          label: "Start here",
          items: [
            { label: "Introduction", slug: "docs" },
            { label: "Getting started", slug: "docs/getting-started" },
            { label: "Embed in Axum", slug: "docs/embedding" },
            { label: "Feature status", slug: "docs/features" },
          ],
        },
        {
          label: "Authentication",
          items: [{ autogenerate: { directory: "docs/guides" } }],
        },
      ],
    }),
  ],
});
