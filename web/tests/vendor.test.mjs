import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { readFile } from "node:fs/promises";
import test from "node:test";

test("vendored bytes, recorded provenance, and HTML integrity stay consistent", async () => {
  const root = new URL("../assets/vendor/", import.meta.url);
  const manifest = JSON.parse(await readFile(new URL("manifest.json", root), "utf8"));
  const html = await readFile(new URL("../index.html", import.meta.url), "utf8");
  for (const dependency of Object.values(manifest)) {
    const bytes = await readFile(new URL(dependency.file, root));
    assert.equal(createHash("sha256").update(bytes).digest("hex"), dependency.sha256);
    const sri = "sha384-" + createHash("sha384").update(bytes).digest("base64");
    assert.equal(sri, dependency.sri);
    assert.ok(html.includes(`/assets/vendor/${dependency.file}" integrity="${sri}"`));
    assert.ok((await readFile(new URL(dependency.license, root))).length > 0);
  }
});
