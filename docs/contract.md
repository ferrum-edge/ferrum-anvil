# API contract (`anvil-contract`)

`crates/anvil-contract` does two things with OpenAPI descriptions:

- **API standards** (this page up to [Contract drift](#contract-drift)):
  checks a description against the rules a team sets for all its APIs.
- **[Contract drift](#contract-drift)**: compares what an API was seen doing
  (sends in Anvil's history, or a HAR capture) with what its description
  says, and suggests revisions to the description.

**API standards** are rules about what every description in the company
must look like (naming, versioning, security, error formats, documentation). A
standard is a *ruleset* file, written once and shared, for example in the
repository that holds the API descriptions. Anvil reports where a
description breaks a rule, with the line to edit and how to fix it.

It reads Swagger 2.0 and OpenAPI 3.0, 3.1 and 3.2, in JSON or YAML. Rules are
written against version-neutral *targets* (operations, parameters,
responses, schemas, …), so one standard applies to every dialect: the same
API described in Swagger 2.0 and in OpenAPI 3.1 breaks the same rules at the
same places (`crates/anvil-contract/tests/lint.rs`).

```bash
anvil lint-spec openapi.yaml                                    # Anvil's recommended rules
anvil lint-spec openapi.yaml --ruleset company.yaml --ruleset team.yaml
anvil lint-spec openapi.yaml --ruleset company.yaml --format sarif --output lint.sarif
```

`samples/api-standards/acme-api-standards.yaml` is a complete example of a
company ruleset.

## Guarantees

- **No I/O.** Specs and rulesets are parsed from the bytes the caller passes,
  under the importer's bounds (size, node count, nesting depth, see
  [import.md](import.md#trust-and-safety-policy)). External `$ref`s are never
  fetched; `extends` names built-in rulesets only.
- **Bounded.** `$ref` chains (32 deep), rules per rule set (2,000), ruleset
  size (1 MiB), example validations (1,000 per lint), property nesting (24
  levels) and findings are capped, and every walk over the document is
  linear in its size. A member name longer than 4 KiB, or member names whose
  JSON Pointers add up to more than 64 MiB, refuse the spec (positions and
  targets keep one pointer per member). Each `$ref` string is followed
  once per spec and remembered, so many references that share a chain
  follow it once, and a Path Item that many paths `$ref` is read once. Each
  use of a reference still reads the value it ends at and copies its
  pointer: that is charged, with the reference, to the budgets below before
  it is done. Regular expressions, in rules and
  in the `pattern`/`patternProperties` of schemas, use the linear-time
  `regex` crate with a size limit; a schema whose pattern needs look-around
  or a back-reference is not used to check examples.
- **Example schemas are checked before use.** References are followed
  without recursion, and a schema is not used when:
  - references form a cycle that does not descend into the value
    (`A: allOf [B]`, `B: allOf [A]`, or `dependentSchemas` back to itself).
    The OpenAPI 3.0 polymorphism pattern `Pet: oneOf [Cat]`,
    `Cat: allOf [Pet]` is such a cycle;
  - a chain has more than 32 references, or 512 levels of nesting along
    one;
  - it expands to more than 100,000 nodes with every `$ref` expanded
    (repeated references count each time);
  - it and the schemas it references have more than 1,000,000 members and
    items (a large `enum` passes; a pathological one is not scanned on
    every compile), or more than 16 MiB of member names and strings (each
    compile copies them, however few members hold them: a description of
    several megabytes, say).

  Examples behind such a schema are counted in `examples_not_checked`. A
  schema is compiled once however many media types `$ref` it, and all the
  compiles of a lint scan 20,000,000 members and items, and 320 MiB of
  names and strings, at most; examples past that are counted as not checked
  too.
- **Operations are bounded too.** They look at 2 million parameters,
  responses and media types at most in all. Inherited path-level
  parameters, the document's security requirements and a shared response's
  headers count for each operation. Past that, the remaining operations are
  counted in `skipped_operations` and not checked. What the targets copy out
  of the description, and the references followed to build them, are
  capped at 256 MiB (an operation reached through several paths counts for
  each); once a copy does not fit, nothing more is checked (an operation
  whose parameters, body or responses do not fit is left out whole), and
  the report says so with `incomplete` (and
  `skipped_operations` for the operations), as do the text, SARIF and
  desktop outputs. `anvil lint-spec` exits with 3 for such a report unless
  `--allow-incomplete` is passed.
- **Unresolvable references are reported, not checked.** An external,
  missing, cyclic or too deep `$ref` is skipped: the parameter, response,
  body or path item behind it is not a target, so no rule reports on the
  `$ref` object itself. The report lists where they are
  (`unresolved_refs`, with a count), and so do the text, SARIF and desktop
  outputs.
- **Checked rulesets.** Every rule, target, function and option is checked
  when a ruleset is loaded; an unknown key or a misspelled target is an
  error naming the rule, never a rule that silently passes.
- **Deterministic.** The same spec and rules give the same report, sorted by
  severity, then line, column and rule.

## Rulesets

```yaml
anvil_ruleset: 1                 # format version (required)
name: Acme API standards         # shown in reports; defaults to the file name
version: "2026.09"
description: What the standard is for.
extends: [anvil:recommended]     # built-in rulesets to start from (optional)
rules:
  info-contact: error            # change an inherited rule's severity
  operation-description: off     # turn an inherited rule off
  acme-property-camel-case:      # a rule of your own
    description: JSON property names are camelCase.
    severity: error              # error | warn | info | hint | off (default warn)
    given: property              # a target, a list of targets, or a JSONPath
    where:                       # optional: the rule applies only when these pass
      field: read_only
      function: falsy
    then:                        # one check or a list of checks
      field: name
      function: casing
      options: { type: camel }
    message: "Property '{{name}}' ({{parent}}) is not camelCase."
    how_to_fix: "Rename it, e.g. `created_at` → `createdAt`."
    docs_url: https://wiki.acme.example/api-standards#naming
    formats: [oas3]              # optional: only for these dialects
```

**Layering.** Rulesets apply in order. Each may extend built-in rulesets,
add rules, replace an earlier rule by defining one with the same id, or
change an earlier rule's severity (`id: warn`, or `id: { severity: warn }`).
Changing the severity of a rule nobody defined is an error, and so is turning
a rule back on once a ruleset turned it off (define it again instead). A
built-in extended by several rulesets is added once, so a later ruleset
never resets the severities an earlier one set. `extends` never reads a
file: layer your own rulesets by passing several (`--ruleset` repeated, or
several enabled rulesets in the desktop).

**Rule ids** use letters, digits, `.`, `_` and `-`.

**`formats`** limits a rule to dialects: `swagger-2.0` (`oas2`),
`openapi-3.0` (`oas3_0`), `openapi-3.1` (`oas3_1`), `openapi-3.2`
(`oas3_2`), or `oas3` for every OpenAPI 3 version. Reports count the rules
skipped this way.

### Checks

A check is `{ field, function, options }`. `then` fails when any check
fails for any selected value; `where` skips the target when any of its
checks fails.

**Fields** are dot-separated names of the target's fields (below). `*`
selects every item of a list or value of a map (`static_segments.*`,
`raw.properties.*.type`), so each item is checked and reported on its own. A
leading `raw.` reads the original OpenAPI object of the target (after `$ref`
resolution) instead of the normalized fields, for dialect-specific or
extension rules (`raw.x-acme-owner`); a finding then points at that exact
member. A `raw.` field is read where it is in the document, not copied,
however large it is and however many paths reach it. Without `field`, the
function sees the whole target.

| Function | Options | Fails when the value… |
|---|---|---|
| `defined` | — | is missing or null |
| `undefined` | — | is set |
| `truthy` | — | is missing, null, `false`, `0`, blank text, or an empty list or map |
| `falsy` | — | is set and not empty (the opposite of `truthy`) |
| `pattern` | `match`, `not_match` (regular expressions) | does not match `match`, or matches `not_match`; numbers and booleans are matched as text, lists and maps fail |
| `casing` | `type`: `camel`, `pascal`, `kebab`, `snake`, `cobol`, `macro`, `flat`; `disallow_digits` | is not written in that case |
| `enumeration` | `values` | is not one of `values` |
| `length` | `min`, `max` | has fewer or more characters, items or members (for a number: is smaller or larger) |
| `alphabetical` | `key` (for lists of maps) | is not sorted, ignoring case (map keys are checked in document order) |
| `includes` | `values`, `pattern` | is a list without every one of `values`, or without an item matching `pattern` |
| `unique` | — | is a list with a repeated item |
| `xor` | `fields` (at least two) | does not have exactly one of the target's `fields` set (it takes no `field`) |
| `schema` | `schema` (JSON Schema 2020-12) | does not validate |

`pattern`, `casing` and `enumeration` pass on a missing value: pair them with
`defined` when the value is required.

**Messages.** Without `message`, a finding reads `<target>: <field> <why>`.
A `message` may use `{{value}}` (the checked value), `{{field}}`,
`{{reason}}` (why the function failed), `{{label}}` (for example `GET
/pets`), `{{rule}}`, `{{pointer}}`, and any field of the target
(`{{path}}`, `{{operation_id}}`, `{{code}}`, …). A list renders as its items
joined by commas.

### Targets

Every target has `extensions` (its `x-*` members). Targets reached through a
`$ref` are reported once, where they are defined. An operation reached through several paths (one Path Item `$ref`'d by each) is a target per path, since each path has its own template.

| Target | One per | Fields |
|---|---|---|
| `document` | description | `dialect` (`openapi-3.1`, …), `openapi_version`, `title`, `version`, `has_servers`, `server_urls`, `tags` (declared names), `security` (global scheme names), `has_global_security`, `path_count`, `operation_count`, `schema_count`, `security_scheme_count`, `json_schema_dialect`, `has_webhooks`, `consumes`, `produces` |
| `info` | description | `title`, `version`, `summary`, `description`, `terms_of_service`, `contact` (`name`, `url`, `email`), `license` (`name`, `url`, `identifier`) |
| `server` | server (document, path and operation level; Swagger: each of `schemes` × `host` + `basePath`) | `url`, `description`, `name`, `variables` (names), `level` |
| `tag` | declared tag | `name`, `summary`, `description`, `parent`, `kind`, `has_external_docs`, `used` |
| `path` | path | `path`, `operations` (methods), `segments`, `static_segments` (segments without `{…}`), `template_params` |
| `operation` | operation (3.2 `query` and `additionalOperations` included) | `method`, `method_upper`, `path`, `operation_id`, `summary`, `description`, `tags`, `deprecated`, `parameters` (`name`, `in`, `required`), `parameter_names`, `query_params`, `header_params`, `path_params`, `cookie_params`, `has_request_body`, `request_content_types`, `response_codes`, `success_codes` (2xx/3xx), `error_codes`, `client_error_codes`, `server_error_codes`, `has_default_response`, `response_content_types`, `security` (effective scheme names), `has_security`, `has_explicit_security`, `callbacks`, and the checks `operation_id_duplicate`, `undeclared_path_params`, `unused_path_params`, `undeclared_tags`, `undefined_security_schemes`, `duplicate_parameters` |
| `parameter` | parameter of an operation (path-level ones merged; a Swagger `in: body` parameter is the request body) | `name`, `in`, `required`, `description`, `deprecated`, `type`, `types`, `nullable`, `format`, `enum`, `style`, `explode`, `allow_empty_value`, `has_schema`, `has_example`, plus the operation's `method`, `method_upper`, `path`, `operation_id` |
| `request_body` | operation with a body (Swagger: `in: body` or `formData`) | `required`, `description`, `content_types`, plus the operation's fields as above |
| `response` | response | `code`, `description`, `content_types`, `headers` (names), `has_content`, `is_success`, `is_error`, `is_default`, plus the operation's fields |
| `header` | response header | `name`, `code`, `description`, `required`, `deprecated`, `type`, `format`, plus the operation's fields |
| `media_type` | body media type (Swagger: `consumes`/`produces` of a body or response with a schema) | `media_type`, `direction` (`request` or `response`), `code`, `has_schema`, `schema_type`, `schema_is_ref`, `has_example`, `example_errors`, plus the operation's fields |
| `schema` | component schema (Swagger `definitions`) | `name`, `type`, `types`, `nullable`, `format`, `title`, `description`, `properties` (names), `required`, `enum`, `has_example`, `deprecated`, `is_ref`, `referenced` |
| `property` | property of a component schema or of an inline body or parameter schema (through `items`, `allOf`/`oneOf`/`anyOf` and `additionalProperties`; `$ref`s are visited as their components) | `name`, `parent`, `required`, `type`, `types`, `nullable`, `format`, `description`, `is_ref`, `deprecated`, `read_only`, `write_only`, `enum`, `has_example` |
| `security_scheme` | declared scheme | `name`, `type`, `scheme`, `in`, `param_name`, `bearer_format`, `flows`, `openid_connect_url`, `description`, `deprecated`, `used` |

`type` is the first non-null type; `types` lists them all and `nullable` is
true for 3.0 `nullable`, Swagger `x-nullable` or a `null` type.
`example_errors` lists the body examples (`example`, `examples.*.value`, 3.2
`dataValue`, Swagger `examples.<media type>`) that do not validate against
their schema, converted to JSON Schema as described under
[Schemas](#schemas); the linter skips examples whose schema uses an external
reference.

**JSONPath.** `given: "$.components.schemas.*.properties.id"` (or `given:
{ jsonpath: … }`) selects raw nodes with an RFC 9535 JSONPath. Fields then
read the selected node (`type`), a scalar node is `value`, and findings point
at the node (or the member a field names).

### Schemas

Examples (and, in live checks, observed payloads) are validated with JSON
Schema 2020-12. OpenAPI 3.1 and 3.2 schemas are used as they are. Swagger
2.0 and OpenAPI 3.0 schemas are converted: `nullable`/`x-nullable` allow
`null`, boolean `exclusiveMinimum`/`exclusiveMaximum` become the numeric
form, siblings of a `$ref` are dropped (those versions ignore them) and the
`file` type accepts anything. A `required` property that is `readOnly` is
not required in a request, and one that is `writeOnly` is not required in a
response. `format` is asserted (`date-time`, `uuid`, `email`, …; unknown
formats such as `int64` are ignored).

### Built-in rules (`anvil:recommended`)

| Rule | Severity | Checks |
|---|---|---|
| `openapi-version-current` | info | the description is not Swagger 2.0 |
| `info-description`, `info-contact` | warn | `info.description`, `info.contact` |
| `info-license` | info | `info.license` |
| `servers-defined` | warn | servers are declared |
| `server-https` | warn | server URLs use HTTPS (loopback excepted) |
| `operation-operation-id`, `operation-summary`, `operation-tags` | warn | each operation has one |
| `operation-operation-id-unique` | error | operationIds are unique |
| `operation-description` | hint | each operation has a description |
| `operation-tag-defined` | warn | operation tags are declared in `tags` |
| `operation-success-response` | warn | a 2xx or 3xx response is declared |
| `operation-parameters-unique` | error | no parameter is listed twice |
| `operation-security-defined` | error | security requirements name declared schemes |
| `path-params-declared`, `path-params-used` | error | path template and `in: path` parameters agree |
| `path-trailing-slash` | warn | no path ends with `/` |
| `path-no-query-string` | error | no path contains `?` |
| `response-description` | warn | each response has a description |
| `media-type-schema` | warn | JSON, XML, form and text bodies have a schema |
| `example-valid` | warn | body examples match their schema |
| `tag-description` | info | declared tags have a description |
| `schema-unused` | info | component schemas are referenced |
| `parameter-description` | hint | parameters have a description |

The file is `crates/anvil-contract/rulesets/recommended.yaml`; it uses the
same format as your rulesets. `anvil lint-spec --list-rules` prints the
rules in effect for the rulesets you pass.

## Reports

`LintReport` (JSON Schema in `contracts/schemas/LintReport.schema.json`) has
the linted spec (`title`, `version`, `dialect`, `sha256`, operations), the
rulesets that took part (name, version, source, SHA-256), how many rules
ran and were skipped, counts per severity, and the findings. Each finding
has the rule, severity, message, the JSON Pointer of the object to change,
its line and column in the source, the target and a label (`GET /pets`,
`property total_amount of Order`), the fix and documentation link the rule
gives, and the ruleset that defined the rule.

Line and column come from the original text. JSON is located exactly; YAML
block mappings and sequences are located to the key or item, and a value
inside a flow collection (`{…}`, `[…]`) or a multi-line scalar is located to
its enclosing member.

At most `max_findings` (default 5,000) are kept, most severe first; the rest
are still counted (`dropped`).

**Not covered.** Webhooks and callbacks are not targets (their operations
are not walked). A Swagger 2.0 document without `schemes` is taken to be
served over `https` (the importer does the same and reports it), and one
without `host` has no `server` target.

## CLI

`anvil lint-spec <SPEC> [--ruleset FILE]... [--format text|json|sarif]
[--output FILE] [--fail-on error|warn|info|hint|never] [--no-examples]
[--list-rules]` needs no profile, so it runs in CI. `-` reads the spec from
stdin. Without `--ruleset`, the recommended rules apply. Exit codes: `0` no
finding at or above `--fail-on` (default `error`), `2` otherwise, `3` a
local error (unreadable file, invalid spec or ruleset, or a description too
large to lint completely, unless `--allow-incomplete`). With `--output`, the
report goes to the file and a summary line to stderr. Text output escapes
control characters and bidirectional overrides in everything that comes
from the spec or a ruleset (errors included), so a message cannot inject a
CI workflow command or a terminal escape sequence; JSON and SARIF output
escape C1 controls, line separators and bidirectional overrides as
`\uXXXX`. The CLI and desktop accept rulesets up to 1 MiB each; the desktop
also bounds the count and aggregate size of stored rulesets.

SARIF 2.1.0 output names each rule (with its fix as help text and its
`http(s)` documentation link) and each finding's file, line and column
(`columnKind` `unicodeCodePoints`). A relative spec path is a URI relative to
`%SRCROOT%`, an absolute one a `file:` URI (`file:///C:/…` on Windows), and
standard input `stdin`. Dropped findings and unresolved
references are tool notifications. Code scanning then annotates the pull
request:

```yaml
- run: anvil lint-spec api/openapi.yaml --ruleset standards/acme.yaml --format sarif --output lint.sarif --fail-on never
- uses: github/codeql-action/upload-sarif@v3
  with: { sarif_file: lint.sarif }
- run: anvil lint-spec api/openapi.yaml --ruleset standards/acme.yaml   # fails the job on errors
```

## Desktop

The **Contract** view lists the workspace's imported OpenAPI and Swagger
descriptions; picking one checks its stored original (the version last
applied by a reimport) against the profile's standards. **Check a spec
file…** checks a file chosen in the native dialog instead, and **Check
again** reads it again. Findings show the message, line, target, fix and
rule; the severity cards filter them. **SARIF** and **JSON** check again and
write the report to a file chosen in the save dialog
(`lint_report_export`).

**API standards** are kept as separate encrypted profile records (included in
workspace bundles and full backups): Anvil's recommended rules, which can be
left out, then each ruleset added with **Add** (a file chosen with purpose
`ruleset`), in order.
A ruleset is checked together with the others when it is added, replaced,
enabled or disabled, or when the recommended rules are left out; a change
that would not load (an overlay changing a rule no remaining ruleset
defines, say) is refused and nothing is kept; each change is one write
transaction, so it never undoes a concurrent one. Each ruleset can be up to
1 MiB, with at most 32 records and 8 MiB total. Existing rulesets in older
profiles migrate from app settings the first time the profile opens. When the stored
rulesets do not load (restored from a backup of another build, say), the
view says why and they can still be disabled or removed. **Rules in effect** lists every rule with its severity,
target and ruleset. The settings dialog never changes the standards: they
change only through their own commands (`standards_*`).

## Contract drift

Live traffic shows where a description falls short of the API it
describes. `anvil_contract::analyze` takes observed exchanges (method, URL,
status, headers, content types, sizes, timing and, when available, the JSON
response body) and the description, and reports each difference once, with
how many exchanges showed it.

```bash
anvil spec-drift openapi.yaml --har traffic.har                         # a capture, no profile
anvil spec-drift --import <import-id>                                   # an imported spec's history
anvil spec-drift openapi.yaml --har traffic.har --revised openapi.revised.yaml --patch drift.json
```

`samples/contract/` has a description (`shop.yaml`) and a capture
(`shop-traffic.har`) that shows most kinds of drift.

### Routing

Each exchange is matched to an operation: its path, after a server's base
path (`servers[*].url` at every level, Swagger `basePath`; server variables
match any segment), against the path templates. Among matching templates,
the one with the most literal segments wins (`/pets/mine` over
`/pets/{id}`, and `/files/{name}.json` over `/files/{name}`), then the
longest base path, then the operation the request was imported from. When
nothing matches, up to three leading segments are tried as an unknown prefix
(an API mounted behind a gateway under `/api`), alone or in front of a
declared base path. For a path nothing declares, a base path with server
variables counts only when the variables have their `enum` or `default`
values. `HEAD` falls back to `GET`. An `OPTIONS` request to a path or method
the description lacks is a CORS preflight and is not checked. Base paths
that differ only in variable names are one base path; 64 are kept at most.

### What is checked

| Kind | Severity | When |
|---|---|---|
| `undeclared_path` | warn | the path matches no template (reported generalized: `/users/123` → `/users/{userId}`; see below) |
| `undeclared_method` | warn | the path is declared, the method is not |
| `undeclared_status` | warn | the status has no response, `4XX`-style range or `default` |
| `undeclared_content_type` | warn | the response's media type is not declared for its status (`type/*` and `*/*` count) |
| `response_schema_mismatch` | error | a complete JSON body does not validate against its schema |
| `undeclared_request_content_type` | warn | a request body's media type is not declared (or the operation declares no body) |
| `undeclared_query_parameter` | info | a query parameter is not declared (unless the operation has a 3.2 `querystring` parameter) |
| `missing_required_parameter` | info | a required query or header parameter was not sent |
| `missing_response_header` | warn | a `required` response header was not returned |
| `slower_than_declared` | error | the exchange took longer than the budget's `max_latency_ms` |
| `response_larger_than_declared` | error | the body was larger than `max_response_bytes` |
| `request_larger_than_declared` | warn | the request body was larger than `max_request_bytes` |
| `undeclared_server` | info | the request went to an origin none of the absolute servers matches |
| `deprecated_operation_called` | info | the operation is `deprecated` |

Schema checks use the conversion described under [Schemas](#schemas) in the
response direction (`writeOnly` properties are not required). Validation
messages never quote the body: they name the place (`` `/items/*/id` ``), the
declared constraint and the observed JSON type. In a place, only keys the
schema names under `properties` are shown; array indexes and the keys of
maps (`additionalProperties`, `patternProperties`) are `*`, and undeclared
keys that look like data (see below) are not named. A body is checked only
when it was captured completely, decoded, is JSON and at most 1 MiB, and
while the analysis has parsed less than 32 MiB of bodies in all; otherwise a
note says why (history set to keep no response bodies, say). Schema
compiles share the linter's scanning budgets (members and items, and bytes
of names and strings) and body walks for suggestions stop after 2,000,000
values or 1 GiB of references followed and schema pointers copied on the
way, each with a note. Most of those copies last only while a body is
walked, so that budget is larger than the ones for what an analysis keeps. The operations an analysis
matches against are capped at 256 MiB of their paths, pointers and
declared statuses (an operation reached through several paths counts for
each); past that, the rest are left out with a note, and calls to them are
reported as undeclared. Each operation's parameters, request body,
responses and required headers are resolved once, however many paths and
calls reach it, and what that costs (the references followed and what is
copied out of them) is capped at 256 MiB too; past that, calls to the
operations not yet resolved are not checked and their declared statuses
are not listed, each with a note. `spec.operations` counts the operations
left out of matching as well.

**Keeping observed values out.** Findings, suggestions and the
undeclared-endpoint list carry names, status codes, media types, sizes and
times. Telling a name from a value is a heuristic, so these rules keep most
data out but not all of it:

- An undeclared path keeps only segments that are short lower-case words
  (ASCII letters, digits, `-`, `_`, at most 32 characters and one digit:
  `v1`, `orders`, `line-items`). Every other segment (an id, an email, a
  token, a mixed-case or encoded value) becomes a parameter named after the
  segment before it (`/users/{userId}`). Observed paths are not kept, and an
  unknown prefix is shown generalized the same way. A value that is itself a
  short lower-case word (a username, a slug, a tenant name: `/users/alice`)
  stays literal.
- A property or query parameter name is used only when it looks like a name
  (letters, digits and `_ - . $ [ ]`, not starting with a digit, at most 64
  characters and three digits, and not 16 or more characters mixing upper
  case, lower case and digits); others are left out, with a note. A short
  random token that happens to fit (few digits, one case) passes.
- The origin (scheme, host and port) of a request to a server the
  description does not declare is shown, in the finding and in the
  suggestion to declare that server.
- An object whose keys look like data, or that has more than 50 keys, is
  inferred as a map (`additionalProperties` with the values' shape).
- A method that is not an HTTP token of at most 20 characters is shown as
  `(invalid method)`.

**Budgets.** OpenAPI has no field for performance or size, so drift reads
an extension on the operation, its path item or the document (the most
specific wins, key by key):

```yaml
x-anvil-expectations:
  max_latency_ms: 300          # per exchange, start to end of the response
  max_response_bytes: 65536    # decoded body
  max_request_bytes: 1048576
```

### Suggested revisions

Each finding lists the suggestions that would resolve it. A suggestion is a
set of patch operations on the description, written for its dialect
(`produces`/`consumes` and `definitions` in Swagger 2.0, `content` and
`nullable` in 3.0, type lists in 3.1 and 3.2), with a fragment of the
change in the description's syntax.

- **Additions** document what the API does. Most are recommended (selected
  by default): a response for an undeclared status (with the schema inferred
  from the observed bodies), a media type, a property the schema does not
  declare, a query parameter, a request body media type, and a whole
  operation for an undeclared path or method (path parameters typed
  `integer` when every observed value was numeric). A method goes in its
  Path Item field; in 3.2, `query` does too and any other method goes under
  `additionalOperations`; a method the dialect cannot describe gets no
  suggestion. Two additions are offered but not selected, because they
  decide something rather than document it: a server for an undeclared
  origin, and a latency budget from the observed p95 × 1.5 for an
  operation without one.
- **Relaxations** loosen the contract and are never selected by default,
  because the API may be what needs fixing: allowing `null` (an `enum`
  gets `null` among its values too, and a 3.1/3.2 `const` becomes an `enum`
  of the constant and `null`), widening `integer` to `number` (3.1 and 3.2
  add `number` to the type), adding
  observed values to an `enum` (short tokens only, 20 per enum at most),
  making a required property that was sometimes missing optional (an empty
  `required` is removed), and raising a latency, response size or request
  size budget to cover the largest observed value.

A schema that names no properties (a free-form object or a map) or uses
`patternProperties` gets no property suggestions. At most 50 properties are
suggested per schema, 500 schema changes, 50 query parameters per operation
and 2,000 suggestions in all; at most 500 undeclared endpoints, 50
undeclared servers and 20,000 distinct differences are collected. Each cap
adds a note when it is reached; past the 20,000th difference, the counts of
the differences already collected keep growing, but nothing new about them
(suggestions, body walks) is gathered, so the report is partial. A suggestion's id is derived from the
description and the change it makes, so it changes whenever the change does. Each
finding links to the suggestions that resolve it: a schema change is linked
to the validation errors of its own kind (a type, an enum, an undeclared or
a missing required property) at the same place in the body.

Inferred schemas keep only the shape of what was seen (types, properties,
which properties were always present, array items, and `date-time`, `date`,
`uuid`, `email` and `uri` formats when every sample had them), never
values: no examples, defaults or enums come from traffic. A value of more
than one type becomes `oneOf` in 3.0, a type list in 3.1 and 3.2, and an
unconstrained schema in Swagger 2.0, which has neither.

`revise` applies chosen suggestions and returns the whole revised
description in its original syntax, an RFC 6902 JSON Patch from the
original to it, and a digest of the description and the applied
suggestions. YAML is written anew, so comments and formatting of the
original are not kept; the JSON Patch (or each suggestion's fragment) can be
applied to the source by hand instead. Applying every suggestion and
checking the same traffic again leaves only differences the description
cannot fix (a missing required parameter or response header, a deprecated
operation called), which `tests/drift.rs` checks in all four dialects. A
suggestion applies whole or not at all: if one of its operations cannot
apply, none of it is in the revision and it is listed as skipped. Changes
to one schema compose: allowing null, widening a type and adding enum
values extend the `type` and `enum` lists rather than replacing them, so
they hold together in any order. The digest is of the description and the
revised text.

A HAR capture is read up to 64 MiB and 10,000 entries (a note says how many
were left out). Parsed bodies are also capped at 1,000,000 JSON values per
analysis, and when a large body could produce very many validation errors
(many objects against a long `required` list) only its first difference is
reported, with a note.

### History, the desktop and the CLI

For an imported spec, the exchanges are the newest sends (up to 500 in the
desktop, `--limit` in the CLI, at most 1,000, found among the workspace's
newest 20,000 history entries) of its collection: saved
requests imported from it (under the current or an earlier import id),
requests under its import root, or, when the import made its own workspace,
every request of that workspace, so endpoints added by hand are checked
against the same description. Unsaved drafts are not included. The
description is the import's stored original (the version last applied).

In the desktop, an imported spec in the **Contract** view has a **Live
traffic** tab: the differences with their suggestions, the suggestions with
checkboxes (additions preselected), the coverage of every declared
operation (calls, statuses seen, p95, budget) and the endpoints called but
not declared. **Save revised spec…** and **Save JSON Patch…** write the
revision through the save dialog (file purpose `spec_revision_export`).
**Update the import…** previews what reimporting the revision would do to
the collection (new requests, updates, kept edits) and then reimports it as
the import's new version, as `docs/import.md#reimport` describes (conflicts
and removals are kept); the next check runs against the revision. The
update runs the analysis again and applies only if the revision's digest is
the one previewed: new traffic in between refuses it, and the preview must
be opened again. **Save revised spec…** and **Save JSON Patch…** likewise
refuse when a chosen suggestion is not in a fresh report any more (its id
changed with its content), so the file is the revision that was shown. The
response panel shows a **Contract** tab after a send of a request that
belongs to an OpenAPI import, with the differences of that one send.

`anvil spec-drift` prints the same report as text or JSON (`--format`),
writes the revision (`--revised`) and the JSON Patch (`--patch`) with the
recommended suggestions or all of them (`--apply all`), and exits with `2`
when a finding reaches `--fail-on` (default `error`), `3` on a local error.
With `--har` it needs no profile; with `--import` it opens the profile and
reads its history. Text output escapes control characters from the spec
and the traffic.
