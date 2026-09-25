// Generate TypeScript bindings from contracts/schemas/*.schema.json (produced
// by `anvil schema`). All schemas share definitions, so they are merged into
// one root to emit each type exactly once.
import { compile } from "json-schema-to-typescript";
import { readFileSync, readdirSync, writeFileSync } from "node:fs";
import { join } from "node:path";

const dir = new URL("../../../contracts/schemas/", import.meta.url).pathname;
const defs = {};
const props = {};
for (const f of readdirSync(dir).filter((f) => f.endsWith(".schema.json")).sort()) {
  const s = JSON.parse(readFileSync(join(dir, f), "utf8"));
  const name = f.replace(".schema.json", "");
  for (const [k, v] of Object.entries(s.$defs ?? {})) defs[k] = v;
  const { $defs, $schema, ...rest } = s;
  defs[name] = { ...rest, title: name };
  props[name] = { $ref: `#/$defs/${name}` };
}
const root = { title: "AnvilContracts", type: "object", properties: props, additionalProperties: false, $defs: defs };
const ts = await compile(root, "AnvilContracts", {
  bannerComment: "/* Generated from contracts/schemas by scripts/gen-contracts.mjs — do not edit. */",
  additionalProperties: false,
  unreachableDefinitions: true,
  strictIndexSignatures: true,
  style: { printWidth: 120 },
});
writeFileSync(new URL("../src/generated/contracts.ts", import.meta.url), ts);
console.log(`wrote ${Object.keys(props).length} root contracts, ${Object.keys(defs).length} definitions`);
