#!/usr/bin/env node
// Third-party license inventory for the shipped Ferrum Anvil artifacts.
//
//   node scripts/licenses.mjs                 regenerate THIRD_PARTY_LICENSES.md
//   node scripts/licenses.mjs --check         fail if it is stale or a license is not allowed
//   node scripts/licenses.mjs --json <file>   also write a machine-readable report (release evidence)
//
// Scope: Rust crates reachable through normal/build edges from the shipped
// packages (anvil-desktop with its default = release feature set, and the
// `anvil` CLI) on every target platform, plus the npm production dependencies
// bundled into the desktop UI. Dev/test-only dependencies (including the
// E2E-only WebDriver plugin, which is behind the non-default `e2e` feature)
// are excluded because they are not distributed.
//
// License policy is read from deny.toml ([licenses] allow + exceptions) so the
// crate check here and `cargo deny check licenses` cannot drift apart; npm
// packages are held to the same allowlist.
import { execFileSync } from "node:child_process";
import { readFileSync, readdirSync, writeFileSync, existsSync } from "node:fs";
import { dirname, join, relative } from "node:path";
import { fileURLToPath } from "node:url";

const root = join(dirname(fileURLToPath(import.meta.url)), "..");
const OUT = join(root, "THIRD_PARTY_LICENSES.md");
const SHIPPED = ["anvil-desktop", "anvil-cli"];
/** A third-party crate vendored under vendor/ (a path package that is not Anvil's). */
const isVendored = (p) => !p.source && relative(join(root, "vendor"), p.manifest_path).split(/[\\/]/)[0] !== "..";
const args = process.argv.slice(2);
const check = args.includes("--check");
const jsonAt = args.indexOf("--json");
const jsonOut = jsonAt >= 0 ? args[jsonAt + 1] : null;

// ---------------------------------------------------------------- policy
function policy() {
  const toml = readFileSync(join(root, "deny.toml"), "utf8");
  const section = toml.split(/^\[licenses\]\s*$/m)[1]?.split(/^\[(?!\[)[^\]]+\]\s*$/m)[0];
  if (!section) throw new Error("deny.toml has no [licenses] section");
  const allowBlock = section.match(/^allow\s*=\s*\[([\s\S]*?)\]/m);
  if (!allowBlock) throw new Error("deny.toml [licenses] has no allow list");
  const allow = new Set([...allowBlock[1].matchAll(/"([^"]+)"/g)].map((m) => m[1]));
  const exceptions = new Map();
  for (const m of section.matchAll(/\{\s*allow\s*=\s*\[([^\]]*)\]\s*,\s*crate\s*=\s*"([^"]+)"[^}]*\}/g)) {
    exceptions.set(m[2], new Set([...m[1].matchAll(/"([^"]+)"/g)].map((x) => x[1])));
  }
  return { allow, exceptions };
}

// Small SPDX expression evaluator: AND binds tighter than OR, parentheses
// group, legacy "/" means OR, and "X WITH Y" must be allowed verbatim (deny.toml
// lists it that way). Anything it cannot parse or satisfy is reported, never
// silently accepted.
function satisfied(expr, allowed) {
  if (!expr) return false;
  const tokens = expr.replace(/\//g, " OR ").match(/\(|\)|[^\s()]+/g) ?? [];
  let i = 0;
  const peek = () => tokens[i];
  const factor = () => {
    if (peek() === "(") {
      i++;
      const v = or();
      if (tokens[i++] !== ")") throw new Error(`unbalanced SPDX expression: ${expr}`);
      return v;
    }
    let id = tokens[i++];
    if (!id || id === "AND" || id === "OR" || id === ")") throw new Error(`bad SPDX expression: ${expr}`);
    if (peek() === "WITH") {
      i++;
      id = `${id} WITH ${tokens[i++]}`;
    }
    return allowed.has(id);
  };
  const and = () => {
    let v = factor();
    while (peek() === "AND") {
      i++;
      v = factor() && v;
    }
    return v;
  };
  const or = () => {
    let v = and();
    while (peek() === "OR") {
      i++;
      v = and() || v;
    }
    return v;
  };
  try {
    const v = or();
    return i === tokens.length && v;
  } catch {
    return false;
  }
}

// ---------------------------------------------------------------- cargo
function crates() {
  const meta = JSON.parse(
    execFileSync("cargo", ["metadata", "--format-version", "1", "--locked"], { cwd: root, maxBuffer: 256 * 1024 * 1024, encoding: "utf8" }),
  );
  const byId = new Map(meta.packages.map((p) => [p.id, p]));
  const nodes = new Map(meta.resolve.nodes.map((n) => [n.id, n]));
  const start = meta.packages.filter((p) => SHIPPED.includes(p.name) && meta.workspace_members.includes(p.id)).map((p) => p.id);
  if (start.length !== SHIPPED.length) throw new Error(`shipped packages not found: ${SHIPPED.join(", ")}`);
  const seen = new Set(start);
  const queue = [...start];
  while (queue.length) {
    const n = nodes.get(queue.shift());
    for (const d of n?.deps ?? []) {
      const shippedEdge = d.dep_kinds.some((k) => k.kind === null || k.kind === "build");
      if (shippedEdge && !seen.has(d.pkg)) {
        seen.add(d.pkg);
        queue.push(d.pkg);
      }
    }
  }
  return [...seen]
    .map((id) => byId.get(id))
    // Workspace members are Anvil's own code. Vendored third-party crates
    // (vendor/, patched in via [patch.crates-io]) have no registry source but
    // are still third-party and keep their upstream license.
    .filter((p) => p.source || isVendored(p))
    .map((p) => {
      const dir = dirname(p.manifest_path);
      const notices = existsSync(dir)
        ? readdirSync(dir)
            .filter((f) => /^NOTICE/i.test(f))
            .sort()
            .map((f) => ({ file: f, text: readFileSync(join(dir, f), "utf8").trim() }))
        : [];
      return {
        ecosystem: "cargo",
        name: p.name,
        version: p.version,
        license: p.license ?? (p.license_file ? `SEE FILE ${p.license_file}` : null),
        source: isVendored(p)
          ? `${p.repository ?? `https://crates.io/crates/${p.name}/${p.version}`} (vendored with a patch: ${relative(root, dirname(p.manifest_path))})`
          : (p.repository ?? `https://crates.io/crates/${p.name}/${p.version}`),
        notices,
      };
    })
    .sort((a, b) => a.name.localeCompare(b.name) || a.version.localeCompare(b.version, undefined, { numeric: true }));
}

// ---------------------------------------------------------------- npm
function npmPackages() {
  const lock = JSON.parse(readFileSync(join(root, "apps/desktop/package-lock.json"), "utf8"));
  return Object.entries(lock.packages)
    .filter(([path, p]) => path && !p.dev && !p.devOptional)
    .map(([path, p]) => {
      const name = path.replace(/^.*node_modules\//, "");
      return { ecosystem: "npm", name, version: p.version, license: p.license ?? null, source: `https://www.npmjs.com/package/${name}/v/${p.version}`, notices: [] };
    })
    .sort((a, b) => a.name.localeCompare(b.name));
}

// ---------------------------------------------------------------- render
function render(rust, npm, pol) {
  const all = [...rust, ...npm];
  const summary = new Map();
  for (const c of all) summary.set(c.license ?? "(none declared)", (summary.get(c.license ?? "(none declared)") ?? 0) + 1);
  const exceptionRows = rust.filter((c) => pol.exceptions.has(c.name));
  const esc = (s) => String(s).replace(/\|/g, "\\|");
  const table = (rows) =>
    ["| Component | Version | License | Source |", "| --- | --- | --- | --- |", ...rows.map((c) => `| ${esc(c.name)} | ${esc(c.version)} | ${esc(c.license ?? "(none declared)")} | ${c.source} |`)].join("\n");
  const lines = [
    "# Third-party licenses",
    "",
    "<!-- Generated by `node scripts/licenses.mjs` — do not edit by hand. CI fails when this file is stale. -->",
    "",
    "Ferrum Anvil itself is licensed under the PolyForm Noncommercial License 1.0.0, with a separate commercial",
    "license for commercial use (see `LICENSE` and `LICENSE-COMMERCIAL.md`). The components listed here remain",
    "under their own licenses.",
    "",
    "**Scope.** Rust crates compiled into the shipped binaries — the desktop app (`anvil-desktop`, release feature set)",
    "and the `anvil` CLI — on any supported platform, and the npm packages bundled into the desktop UI. Build-only",
    "tooling, test-only and development dependencies (including the E2E-only WebDriver plugin) are not distributed and",
    "are not listed. Inputs: `Cargo.lock` via `cargo metadata --locked` and `apps/desktop/package-lock.json`.",
    "",
    "**Policy.** Every component must satisfy the permissive allowlist in `deny.toml` (`[licenses] allow`), or be a",
    "reviewed per-crate exception. `cargo deny check licenses` enforces the same list for the whole Rust graph.",
    "",
    "## Summary",
    "",
    `${rust.length} Rust crates, ${npm.length} npm packages.`,
    "",
    "| License expression | Components |",
    "| --- | --- |",
    ...[...summary.entries()].sort((a, b) => b[1] - a[1] || a[0].localeCompare(b[0])).map(([l, n]) => `| ${esc(l)} | ${n} |`),
    "",
    "## Reviewed weak-copyleft exceptions",
    "",
    "These crates are MPL-2.0 (file-level copyleft). They are used unmodified from crates.io; their source, including",
    "any MPL-covered file, is available at the linked location. Modifying one of these files would require publishing",
    "the modified file under MPL-2.0.",
    "",
    table(exceptionRows),
    "",
    `## Rust crates (${rust.length})`,
    "",
    table(rust),
    "",
    `## npm packages bundled into the desktop UI (${npm.length})`,
    "",
    table(npm),
    "",
    "## Notices",
    "",
    "NOTICE files shipped by the components above, reproduced verbatim.",
    "",
  ];
  for (const c of all) {
    for (const n of c.notices) {
      lines.push(`### ${c.name} ${c.version} — ${n.file}`, "", "```text", n.text, "```", "");
    }
  }
  return lines.join("\n");
}

// ---------------------------------------------------------------- main
const pol = policy();
const rust = crates();
const npm = npmPackages();
const violations = [...rust, ...npm].filter((c) => {
  const allowed = new Set([...pol.allow, ...(c.ecosystem === "cargo" ? (pol.exceptions.get(c.name) ?? []) : [])]);
  return !satisfied(c.license, allowed);
});
const text = render(rust, npm, pol);
if (jsonOut) {
  writeFileSync(
    jsonOut,
    JSON.stringify(
      {
        format: "anvil-license-report",
        version: 1,
        scope: { rust_roots: SHIPPED, npm: "apps/desktop production dependencies" },
        policy: { allow: [...pol.allow].sort(), exceptions: Object.fromEntries([...pol.exceptions].map(([k, v]) => [k, [...v]])) },
        violations: violations.map(({ ecosystem, name, version, license }) => ({ ecosystem, name, version, license })),
        components: [...rust, ...npm].map(({ notices, ...c }) => ({ ...c, notice_files: notices.map((n) => n.file) })),
      },
      null,
      2,
    ) + "\n",
  );
}
let failed = false;
if (violations.length) {
  failed = true;
  console.error("License policy violations (not satisfiable by the deny.toml allowlist or a per-crate exception):");
  for (const v of violations) console.error(`  ${v.ecosystem} ${v.name} ${v.version}: ${v.license ?? "(none declared)"}`);
}
if (check) {
  const current = existsSync(OUT) ? readFileSync(OUT, "utf8") : "";
  if (current !== text) {
    failed = true;
    console.error(`${relative(root, OUT)} is stale — run \`node scripts/licenses.mjs\` and commit the result.`);
  } else {
    console.log(`${relative(root, OUT)} is up to date (${rust.length} crates, ${npm.length} npm packages).`);
  }
} else {
  writeFileSync(OUT, text);
  console.log(`wrote ${relative(root, OUT)} (${rust.length} crates, ${npm.length} npm packages)`);
}
process.exit(failed ? 1 : 0);
