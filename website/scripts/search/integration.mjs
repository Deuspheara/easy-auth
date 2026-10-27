import * as pagefind from "pagefind";
import { fileURLToPath } from "node:url";
import { writeBundle } from "./output.mjs";

function checked(response) {
  if (!Array.isArray(response.errors) || response.errors.length) {
    throw new Error("Pagefind indexing failed");
  }
  return response;
}

export async function buildSearch({ dir, logger }) {
  try {
    const { index } = checked(await pagefind.createIndex());
    const { page_count: pages } = checked(
      await index.addDirectory({ path: fileURLToPath(dir) }),
    );
    if (!Number.isSafeInteger(pages) || pages <= 0)
      throw new Error("No search pages indexed");
    const { files } = checked(await index.getFiles());
    // No backend disk writes are pending: complete bytes crossed the service
    // boundary. Closing it cannot truncate Node's awaited writes/readback below.
    await pagefind.close();
    const assets = await writeBundle(fileURLToPath(dir), files);
    logger.info(
      `Verified search index: ${pages} HTML files, ${assets} complete assets.`,
    );
  } finally {
    await pagefind.close();
  }
}

/** @param {import('astro').AstroIntegration} integration */
export function verifiedSearch(integration) {
  if (
    integration.name !== "@astrojs/starlight" ||
    typeof integration.hooks?.["astro:build:done"] !== "function"
  ) {
    throw new Error("Unexpected Starlight search integration");
  }
  // Adapt only the pinned integration's writer hook. Its config, components,
  // search UI, indexing defaults and every other Astro hook remain unchanged.
  return {
    ...integration,
    hooks: { ...integration.hooks, "astro:build:done": buildSearch },
  };
}
