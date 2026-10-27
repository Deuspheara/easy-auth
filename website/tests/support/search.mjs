// Shared only by search build tests: ordinary public HTML, no application state.
import assert from "node:assert/strict";
import * as pagefind from "pagefind";

export async function searchFixture() {
  try {
    const created = await pagefind.createIndex();
    assert.deepEqual(created.errors, []);
    const added = await created.index.addHTMLFile({
      url: "/docs/",
      content:
        '<html lang="en"><head><title>Owned search control</title></head><body data-pagefind-body><h1>SAML recovery</h1><p>Scoped owned documentation search fixture.</p></body></html>',
    });
    assert.deepEqual(added.errors, []);
    const result = await created.index.getFiles();
    assert.deepEqual(result.errors, []);
    return result.files;
  } finally {
    await pagefind.close();
  }
}
