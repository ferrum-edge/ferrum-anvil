# Imports (`anvil-import`)

`crates/anvil-import` turns API descriptions and other clients' exports into
Anvil workspace objects (`Workspace`, `Folder`, `RequestDefinition`,
`Environment`) plus an `ImportReport`.

```rust
let detected = anvil_import::detect(&bytes);             // kind + dialect, no import
let result = anvil_import::import(&bytes, &ImportOptions::default())?;
// generated_hashes: ImportedScope::unit_hashes() plus request_unit_hashes() of what was imported last
let scope = ScopeDiff { current: &stored_scope, generated: Some(&generated_hashes), fresh: &fresh_scope };
let plan = anvil_import::reimport_diff(&existing_requests, &fresh_result, scope);
let merged = plan.apply(&existing_requests, &ReimportApproval::default());
let merged_scope = plan.apply_scope(&stored_scope, &fresh_scope, &ReimportApproval::default());
```

Nothing is persisted or sent by the crate. The caller shows a preview (objects
plus report), lets the user choose, stores the original bytes as a
content-addressed attachment keyed by `ImportedSource::sha256`, and saves.

## Trust and safety policy

| Rule | How it is enforced |
|---|---|
| No network or file I/O during import | The crate has no I/O code paths. External `$ref`s, `wsdl:import`, `xsd:import`/`include`/`redefine` with `schemaLocation`, `externalValue` examples, OpenID Connect discovery URLs, `oauth2MetadataUrl`, Postman/Insomnia/cURL file references are listed in `report.external_refs` with every location that uses them and `requires_approval: true`. Resolving one is a separate, explicit, per-reference user action outside this crate. |
| Safe XML | WSDL is parsed with `roxmltree` with DTDs refused (`allow_dtd: false`): internal/external entity declarations fail the import with `ImportError::UnsafeXml`; undeclared entities are syntax errors. Node count is bounded. |
| Nothing becomes active by import | Pre-request/test/after-response scripts and Insomnia unit tests are copied verbatim into `report.scripts` with `enabled: false, trusted: false` and never attached to requests. TLS-verification bypass (`curl -k`, Postman `strictSSL: false`), credential forwarding across redirects (`--location-trusted`, `followAuthorizationHeader`) and OpenAPI callbacks are listed in `report.inactive_settings` and never applied. Imported requests are never sent. |
| No invented credentials | Auth is imported as configs whose secrets are `{{variable}}` references, listed in `report.required_variables` and deliberately *not* defined, so a request fails validation (unresolved variable) until the user supplies a value. Credential-like body fields and parameters are never generated in samples. |
| Credential redaction (migrations) | Literal credentials in HAR, cURL, Postman and Insomnia input (Authorization/Cookie/API-key-like headers, credential-like query parameters, form fields and JSON members, auth helper secrets, secret variables, cached OAuth tokens) are replaced by `{{placeholder}}` variables and listed in `report.redactions`, unless `ImportOptions::include_credentials` is set (kept values are then marked sensitive). A value that is only variable references plus an auth scheme word (`Bearer {{token}}`) is not a literal secret and is kept. Detection is name-based and best effort; bodies that cannot be scanned (XML, arbitrary text, unparsable JSON) produce a `body_not_scanned` warning. |
| Bounded work | `max_bytes` (input size), `max_nodes` (parsed JSON/YAML nodes — charged *during* deserialization, so YAML alias bombs are refused — and XML nodes), the string bytes a parsed JSON/YAML document keeps (string values and map keys, alias expansions included; at most twice `max_bytes`, charged before each copy), a fixed nesting-depth limit, `max_ref_depth` (direct `$ref`s and those followed while merging `allOf`), `max_ref_expansions` (whole import), `max_sample_nodes` (per payload; also charged per `allOf` branch, and for WSDL per schema node looked at: each child of a construct, each element, attribute, group reference, extension base and message part), bytes generated or copied into OpenAPI samples (generated values at about 32 bytes each plus their text, examples, defaults, merged schemas, per-operation parameters, and the schema lists a sample reads on each visit: a byte per member, `required` name or `enum` value looked at plus its name's length, and the size of `const` once per `enum` value it is compared with; four times `max_bytes` per import), generated WSDL envelope bytes (8 MiB per envelope, four times `max_bytes` per import), at most 1024 `xmlns` occurrences in an XML document (counted in the text before it is parsed) and 256 XML namespaces in scope of any element, `max_operations`. Byte budgets are charged before the copy is made. Malformed input yields an `ImportError`, never a panic (property-tested). |

## Report

Every entry has a location: an RFC 6901 JSON Pointer into the parsed JSON/YAML
(`/paths/~1pets/post/requestBody`), an element path for WSDL
(`/definitions[@name='X']/binding[@name='Y']/operation[@name='Z']`) or an
argument index for cURL (`/args/7`).

* `warnings` — imported with a caveat (recursion cut, composition branch
  chosen, pattern not enforced, alternatives not generated, contradictory
  constraints, redirected pointers).
* `unsupported` — present in the source but not imported or not represented.
* `external_refs`, `scripts`, `inactive_settings`, `redactions`,
  `required_variables` — see above.
* `counts` — operations found/imported/skipped, `$ref` resolutions and the
  sizes of every list.

Codes are stable strings (for example `recursive_schema`,
`composition_first_branch`, `contradictory_schema`, `openapi32_construct`,
`file_part_requires_attachment`, `dynamic_variable`, `template_tag`).

## Determinism and identity

* Ids are UUIDv5 values derived from a namespace and a stable key
  (`request|<operation key>`, `folder|tag:<name>`, …). The namespace is derived
  from the input's SHA-256 and the content-affecting options unless the caller
  passes `ImportOptions::id_namespace` (do this with the previous import's
  `ImportedSource::id_namespace` when reimporting, so unchanged folders and
  requests keep their ids).
* Samples use a SplitMix64 stream seeded from `seed` and the operation key:
  the same input and seed give identical output, and adding or removing an
  operation does not change the samples of the others.
* Timestamps come from `ImportOptions::imported_at` (current time when unset);
  everything else is a pure function of the input and options.
* `ImportSource::operation_key` is the operationId (else `METHOD path`) for
  OpenAPI, `service/port/operation` for WSDL, the item id for Postman and
  Insomnia, `har:<index>:<METHOD url>` (query dropped) for HAR and
  `curl:<METHOD url>` for cURL. Duplicates get a `#n` suffix and a warning.
* `ImportSource::generated_hash` is SHA-256 of the canonical JSON (sorted
  keys, no whitespace) of the generated `RequestSpec` with `source` removed
  (`anvil_import::spec_hash`).

## Persisting an import (`anvil-app`)

`App::spec_import` gives every import its own fresh `id_namespace` (any
namespace in the caller's options is ignored) and keeps it in the stored
source record. Only a reimport of that import (`spec_reimport_plan` /
`spec_reimport_apply`) reuses it. Importing the same source again, into the
same or another workspace, therefore creates an independent copy and never
moves or overwrites an earlier import's requests. An import that would still
overwrite a stored object is refused.

The import is atomic. A restore checkpoint is taken first; then the new
workspace or root folder, the original bytes (a stored attachment), folders,
requests, environments and the source record are written in one
transaction. If anything fails, including taking the checkpoint, nothing is
written.

### The import root

Imported into an existing workspace, the objects go under a new top-level
folder, the *import root* (`Folder::import_root`). It carries the source's
workspace-level scope: description, settings, variables and auth (an
explicit `none` when the source has no auth). Imported environments are added
to the destination workspace and listed on the import root
(`import_environment_ids`).

The import root is a boundary. A request under it resolves only the imported
collection's own scope (`App::build_context`):

- variables of the import root and the folders under it, and of an
  environment the import brought, when that one is selected;
- auth of the import root, the folders under it and the request;
- in a collection run or load chain, values extracted in the same iteration
  by requests under the same import root.

Everything else is left out, secret or not:

- the destination workspace's variables and auth, and folders above the
  import root;
- every other environment, including the destination's active one, even when
  chosen for a send;
- values extracted by requests outside the import root, and the dataset row
  of the run or load plan. When a run or load test with a dataset includes a
  request under an unopened import root, the rows are not applied to it and
  the report says so in a note;
- this device's identity: a JWT-SVID from the SPIFFE Workload API or a token
  file is refused, and so is a TLS profile whose client identity (a
  certificate or this device's X.509-SVID) is bound to no host. Both the
  request's own TLS profile and the selected proxy's count, whatever the
  proxy's kind (HBONE included) or `no_proxy`, so the check does not depend
  on the destination.

It works the other way too: a value extracted under the import root is not
visible to the workspace's own requests. Each prepared request carries the
import root it was sealed under (`ExecutionContext::scope`, `None` outside
one), and the runner and load executor hand a step only the extracted values
of its own scope. Requests that are not under an import root are unaffected.

So an imported `Bearer {{token}}` can never pick up the destination's
`token`, whether it is a destination variable or a value the destination's
own login request extracted earlier in the same run. It stays unresolved and
the request is not sent.

**Opening an import root.** The user can open an import root to its
workspace on this device (`use_workspace_scope`, set only by
`App::set_import_root_workspace_scope` and the desktop command
`folder_set_workspace_scope`). The workspace's variables, active environment
and auth, this device's workload identity and TLS client identities, and the
run's extracted values and dataset rows then apply under it as under any
folder. An import never sets it: a spec import creates the root with it off,
saving a folder keeps the stored value, and a bundle import turns it off with
a warning (the import root itself is kept).

In the desktop, the import root's folder settings have a **Workspace scope**
tab; ordinary folders have none. It shows whether the collection is isolated
(the default) or opened, what its requests always resolve and what they
resolve only once opened, and why an imported `{{token}}` defined only by the
workspace stays unresolved. **Open to workspace…** asks for confirmation
first; **Isolate again** takes effect at once. The change is saved
immediately, apart from the dialog's **Save**, and a refused change (for
example, a locked profile) is shown in the tab and leaves the scope as it was.

**Variable precedence.** In a workspace of its own, the source's collection
variables are workspace variables, below the environment. Under an import
root they rank the same way: workspace variables (only when opened), then
folders above the import root (only when opened), then the import root's
variables, then the environment, then the folders under the import root and
the run's iteration values. An existing-workspace import therefore prepares
exactly like a new-workspace import of the same source.

**Settings that still apply.** TLS trust (verification, roots, minimum
version), proxy profiles, DNS overrides and gateway profiles selected by the
destination workspace or an outer folder still apply under an import root. A
TLS profile with a client identity applies only when it is bound to hosts,
and then presents the identity only to those hosts. A proxy's own TLS profile
is used only for the connection to the proxy, under the same host-binding
rule.

**Cookies and OAuth tokens** are kept per workspace, not per import root.
Every request in the workspace shares its cookie jar, and cookies follow the
usual domain, path and `Secure` rules, so a cookie never reaches a host it
was not set for. An OAuth token is cached under the workspace, every setting
that decides what it authorizes (issuer, client, grant, audience, scope) and
the workspace, folder or request that defines the profile (`token_cache_id`).
An imported profile is therefore cached apart from the workspace's own, and
opening or closing the import root does not drop a token already acquired.

## Reimport

`reimport_diff(previous, fresh, scope)` links requests by operation key and
classifies each previously imported request:

| Upstream changed | User edited (spec hash ≠ `generated_hash`) | Result |
|---|---|---|
| no | no | `unchanged` |
| no | yes | `preserved_edits` (kept) |
| yes | no | `updated` (safe; applied by `apply`) |
| yes | yes | `conflicts` (kept unless the id is in `ReimportApproval::overwrite`) |
| gone | — | `removed` (kept unless the id is in `ReimportApproval::delete`) |

New operations are `added` (with the fresh folders they need in
`added_folders`); requests without an import link are `unlinked` and untouched.
`apply` keeps ids, folders, ordering and favorites of existing requests and
moves added requests into the existing workspace. A request whose spec is
updated loses its `revision_id`, since that revision holds the old spec.
Changing the sample mode or seed between imports changes generated hashes;
every operation then shows up as changed upstream.

### Renames

A request's name, description and tags are not part of its spec hash, so
each is compared on its own by the same rule as the spec: as stored, as
generated last time and as generated now. The table above applies to each of
these parts, and a request is classified by all of them together:

- a part that differs only because the user changed it (a rename, say) is a
  preserved edit, and is kept;
- a request with a part changed upstream is `updated` when the user changed
  none of the parts that changed upstream, and a conflict when the user
  changed one of them;
- applying a change (a safe update, or an approved conflict) writes only the
  parts that changed upstream (`ReimportChange::upstream_fields`: `spec`,
  `name`, `description`, `tags`) and keeps the rest as the user left it;
- a declined conflict keeps only the parts that conflict
  (`ReimportChange::conflicting_fields`: those changed both upstream and by
  the user). The other parts that changed upstream are still written, as a
  safe update would write them.

So a request the user renamed keeps the user's name when only its spec
changed upstream (the spec is still updated), and a rename upstream of a
request the user also renamed is a conflict kept until its id is in
`ReimportApproval::overwrite`. If its spec changed upstream too and the user
did not edit the spec, declining the conflict still updates the spec and
keeps only the user's name; the name conflict is offered again next time. A
rename upstream of a request the user did not rename is a safe update. `changed_fields` lists the differing spec fields,
then `name`, `description` and `tags` when they differ.

What was generated is recorded with the scope's hashes:
`request_unit_hashes(requests)` gives a hash per part, keyed
`requests/<operation key>/name` (`…/description`, `…/tags`), kept in the same
map and passed in `ScopeDiff::generated`. A part whose hash is missing there is
unknown: when it differs, it counts as changed both upstream and by the user,
so it awaits approval. A removed request is `user_edited` when its spec or one
of these parts was edited.

### Scoped configuration

An import also writes configuration outside its requests (`ImportedScope`):
the source's own description, settings, variables and auth, its environments
and its folders. An OpenAPI server is an environment whose `baseUrl` the
requests reference as `{{baseUrl}}`, so a changed server changes no request
and is found here instead. `reimport_diff` compares it in units, each with a
stable key: `description`, `settings`, `auth`, `variables/<name>`,
`environments/<id>` (the environment's name),
`environments/<id>/variables/<name>`, `folders/<id>` (the folder's name),
`folders/<id>/description`, `folders/<id>/settings`, `folders/<id>/auth` and
`folders/<id>/variables/<name>`. A repeated variable name gets a `#n`
suffix.

Folder units cover what a source configures on a folder: a Postman folder's
description, variables and auth, and an OpenAPI tag's description (the tag's
folder). They are compared only for a folder both sides have. A folder only
the fresh import has arrives with the requests added in it
(`added_folders`); one only the store has (gone from the source, or deleted by
the user) is left alone and not listed. `apply_scope` changes only the
compared units of a folder; its place, order and the rest stay. An environment only one side has (added or removed, upstream or by
the user) is one unit, with its variables (`ScopeChange::whole_environment`):
whether it changed upstream, and whether the user edited it, is judged on its
name and all its variables together. An environment the user deleted is so a
conflict when the source changed any of it (its `baseUrl`, say), and one
removed upstream is `user_edited` when the user changed any of its variables.

Nothing on those objects records what was generated, so the caller keeps
`ImportedScope::unit_hashes()` of what the import generated and passes it back
as `ScopeDiff::generated`. Each unit is then classified as a request is, into
`scope_updated`, `scope_conflicts` (applied only when the key is in
`ReimportApproval::overwrite_scope`), `scope_preserved_edits` and
`scope_removed` (deleted only when the key is in
`ReimportApproval::delete_scope`). A variable or environment the user added
is a preserved edit. Without a record of what was generated, every difference
is a conflict or a removal awaiting approval. `apply_scope` returns the merged
scope: variables are replaced in place, and a new environment arrives whole.
`next_generated_scope(fresh_scope, fresh_requests, generated, approval)` gives
the hashes to keep after applying: the fresh import's (its scope's and its
requests' names, descriptions and tags), except that a declined conflict or
removal keeps its earlier hash (for a whole environment, those of it and its
variables), so it is offered again next time, as a declined request conflict
is. A removed request that is kept keeps the earlier hashes of its name,
description and tags; a declined request conflict keeps those of the parts in
its `conflicting_fields`, and gets the fresh hashes of the parts it applied.
A declined conflict with
no earlier hash is offered again too. A declined removal with no earlier hash
(a unit that, as far as is known, only the user had) is left out, so the next
reimport keeps it as the user's own instead of offering to delete it again.

### Reimport in the app

`App::spec_reimport_plan` and `App::spec_reimport_apply` run the importer in
the import's own id namespace, so unchanged operations and environments keep
their ids. The scope compared is the new workspace's, or the import root's in
an existing workspace (an explicit "no auth" there stands for a source without
auth, as at import), plus the environments the import brought and its folders
that are still stored. The generated hashes, of the scope and of the
requests' names, descriptions and tags, are kept in the source record
(`SpecSourceRecord::generated_scope`); a record written by an earlier build
without them gets them by importing its stored original again, unless it was
reimported since or that original cannot be read; then they are unknown, and
every difference awaits approval. A record written by a build that kept only
the scope's hashes (no `folders/…` or `requests/…` units) gets those units the
same way. A reimport of an import root that was deleted is refused.

The apply is one transaction after a restore checkpoint. It first reads the
linked requests, the workspace's or import root's scope, the environments and
the source record again, with the folders it compared; if any of them changed
since the diff was made (a folder renamed or its variables edited, say), the
apply is refused with nothing written ("changed since the diff; re-run the
reimport diff"). It then writes updated and added requests, the merged scope
onto the workspace or import root, changed folders, and changed or added
environments, which are added to the import root's `import_environment_ids`. An environment
deleted with approval is removed from there too; when it was the workspace's
active environment, none is active afterwards, as when the user deletes an
environment. Every request whose spec changes gets a new
immutable revision, and the request points at it, so a send, run or history
record names the spec actually sent; the old revision is left as it was, and
a request the reimport leaves unchanged keeps its revision.

The same transaction refreshes the source record
(`App::spec_reimport_apply(import_id, bytes, file_name, approval)`): the
bytes just applied are stored as the original attachment, and the record's
`original_sha256`, `file_name` and `source` (hash, size, title, declared
version and import time of that file, and the new import id) describe them.
The earlier import id is appended to `previous_import_ids`, and the id
namespace stays the same. Anything that reads the stored original afterwards
reads the version last applied. The original it replaces is released in the
same transaction, by the same reference check as `App::release_attachment`:
it is deleted unless another object still references it (another import of
the same bytes, a request body, a revision, a dataset, a scenario or a load
plan) or a user attached the same file, which a request or dataset not saved
yet may hold (see `docs/storage-and-recovery.md`). A refused apply leaves the
record, and the earlier original, as they were.

## OpenAPI and Swagger

Dialects are detected from the `openapi`/`swagger` field and handled
explicitly: `swagger-2.0`, `openapi-3.0`, `openapi-3.1`, `openapi-3.2`. Any
other version (for example 3.3 or 4.0) is refused with
`ImportError::UnsupportedDialect`; 3.2 is never treated as 3.1.

**Structure.** `info.title`/`version`/`summary`/`description` → workspace.
Each server becomes an environment with `baseUrl` and the server variables
(defaults as values, enums and descriptions in the variable description);
3.2 server `name` is the environment name; `server_index` picks the active
one. Relative server URLs become `{{origin}}/…` with `origin` required.
Swagger 2.0 `schemes` × `host` + `basePath` become environments (https is
assumed and reported when `schemes` is missing). Path- and operation-level
`servers` override the URL with defaults inlined (reported).
Grouping by first tag (declared tag order, descriptions; 3.2 `parent` tags
nest, cycles reported) or by first path segment; untagged operations stay at
the top level. Path Item `$ref` (3.1 `components/pathItems`), path-level
parameters merged with operation parameters (operation wins), methods
`get…trace`, 3.2 `query` and `additionalOperations`. Operation `summary` →
name, `description` → description, tags kept, `deprecated` marked. The first
2xx/`default` response media type (Swagger: `produces`) becomes `Accept`.

**Parameters.** Path (`simple`, `label`, `matrix`), query (`form`,
`spaceDelimited`, `pipeDelimited`, `deepObject`), header (`simple`), cookie
(`form`, 3.2 `cookie`) with `explode`; `content`-typed parameters are
serialized as JSON; 3.2 `in: querystring` with a form-encoded object;
Swagger 2.0 `collectionFormat` (`csv`, `ssv`, `tsv`, `pipes`, `multi`). Query
values are stored decoded and percent-encoded by the engine at send time, so
non-exploded delimiters are sent encoded (`%2C`, `%7C`, `%20`); form-decoding
servers see the same values. Optional parameters are imported disabled
(enabled with `include_optional`). `Accept`, `Content-Type` and
`Authorization` header parameters are ignored as the specification requires
(reported). Credential-like parameters become `{{name}}` placeholders.

**Bodies.** One media type is generated (JSON family > form > multipart >
XML > text > `*/*` > other; the rest are reported). JSON (vendor `+json`
types keep an explicit `Content-Type`), XML (schema `xml` hints: `name`,
`namespace`, `prefix`, `attribute`, `wrapped`, 3.2 `nodeType`
element/attribute/text/cdata/none), `application/x-www-form-urlencoded` (with
`encoding` style/explode), `multipart/form-data` (files become disabled
placeholder parts; `encoding.contentType` kept), text. Binary media types
(`application/octet-stream`, images) are reported: they need an attachment.
Swagger 2.0 `in: body` and `formData` (file parameters → multipart) are
mapped to the same model.

**Samples** (`SampleMode::Sample`): explicit example (media type
`example`/`examples` incl. `$ref`, 3.2 `dataValue`/`serializedValue`,
parameter examples, schema `example`/3.1 `examples`/`x-example`) → `default`
→ `const` → first `enum` value → seeded generator. The generator honors
`required`; omits `readOnly` members; keeps `writeOnly`; handles `nullable`,
`x-nullable` and type arrays; `minLength`/`maxLength`,
`minimum`/`maximum`/exclusive bounds (both 3.0 boolean and 3.1 numeric
forms), `multipleOf`, `int32`/`int64`, `minItems`/`maxItems`/`uniqueItems`,
`prefixItems`, `minProperties`, `additionalProperties`; formats `date-time`,
`date`, `time`, `duration`, `uuid`, `email`, `hostname`, `ipv4` (TEST-NET),
`ipv6` (documentation prefix), `uri`/`url`/`iri` (example.com),
`uri-reference`, `byte`/base64; `allOf` is merged (conflicting types and
disjoint enums reported), `oneOf`/`anyOf` use the first viable branch (warned;
a discriminator property gets the mapping key), `$ref` with 3.1 siblings is
treated as `allOf` (3.0 siblings are ignored and reported). Recursion stops
at the first repeated `$ref` (`recursive_schema`); an `allOf` branch whose
`$ref` would exceed `max_ref_depth` is left out (`ref_depth_limit`), and
merging stops when the payload budget is spent. Required members that
cannot be produced, and required names with no schema, become `null` with a
warning; each such `null` counts as a generated value, and once a budget is
spent the remaining members are left out. Optional members that are not
generated are skipped before their schema is resolved. `format: password`,
`binary` and credential-like member names are never generated.
Contradictions (min > max, lengths, empty ranges, `const` outside `enum`,
example type mismatches) are reported; the sample is never claimed valid.

**Blank mode** (`SampleMode::Blank`): `""`, `0`, `false`, `[]`, objects with
required members (all members with `include_optional`), path parameters as
`{{name}}` placeholders, empty query/header/cookie values; examples, defaults
and enums are not used.

**Auth.** Global `security` → workspace auth (operations inherit; `security:
[]` → none). apiKey (header/query/cookie), HTTP basic and bearer, OAuth 2
client-credentials and authorization-code (imported as PKCE) with token and
authorization URLs and the requirement's scopes, Swagger 2.0 `basic`/`apiKey`/
`oauth2` (`application`, `accessCode`). Alternatives: the first fully
supported alternative is used (reported when there are several); conjunctions
become `Multi`. OpenID Connect and unsupported OAuth flows (implicit,
password, 3.2 device authorization) become bearer-token placeholders and are
reported; `mutualTLS` is reported (select a TLS profile instead); other HTTP
schemes are reported.

**Reported, not imported:** webhooks (requests the API sends), callbacks
(inactive settings), links, responses, `not`, `if`/`then`/`else`,
`dependent*`, `patternProperties`, `unevaluated*`, `propertyNames`,
`contains` (not enforced), `$dynamicRef`/`$recursiveRef`, `$anchor`/`$id`
plain-name references, custom `jsonSchemaDialect`/`$schema`, `allowReserved`
(values are encoded), 3.2 `itemSchema` streams (one item is emitted),
`prefixEncoding`/`itemEncoding`, `$self`, `oauth2MetadataUrl` discovery,
per-part multipart `headers`. 3.2-only constructs found in 3.0/3.1 documents
(`query`, `additionalOperations`, `querystring`, the `cookie` style, tag
`parent`/`summary`/`kind`, server `name`, `$self`) are reported as
`openapi32_construct` and not honored.

## WSDL 1.1

Services → folders, ports → sub-folders labeled with the SOAP version, binding
operations → requests with `Body::Soap { version, envelope, action }`
(`soapAction`; empty SOAP 1.2 actions are omitted). SOAP 1.1 and 1.2 bindings
(`wsdl/soap/`, `wsdl/soap12/`), document/literal and rpc/literal styles
(rpc wrapper in `soap:body/@namespace`, unqualified part accessors), `parts`
filters, `soap:header` blocks. Port addresses become `<Port>_url` variables
in a "WSDL endpoints" environment; bindings no service exposes are imported
with a required `<Binding>_url` variable.

Envelope generation from inline XSD: global/local `element` (`ref`, `type`,
anonymous types, `minOccurs`/`maxOccurs`, `fixed`, `default`,
`elementFormDefault`/`form`), `complexType` with `sequence`, `all`, `choice`
(first branch, warned), `group` references, `attribute`/`attributeGroup`
(`use`, `fixed`, `default`, `attributeFormDefault`), `complexContent`
extension (base content first) and restriction, `simpleContent`,
`simpleType` restriction with `enumeration`, numeric and length facets,
`list`, `union` (first member, warned), built-in types. Optional elements
appear with `<!--Optional:-->` when `include_optional` is set; repeated
elements are annotated. Recursive types, and `group`/`attributeGroup`
references back to a group being expanded, stop at the first repetition
(`recursive_schema`). An attribute is written once per element. An envelope
that reaches its node or byte budget keeps what was generated so far, still
well-formed (`sample_size_limit`); once the import's envelope budget is
spent, later envelopes are left empty. Credential-like elements
(`password`, …) are left empty. Each binding, binding operation and portType
operation is read once, however many ports use it; the message parts and
`soap:header`s an operation writes are charged to its envelope's budget.

Reported: HTTP GET/POST bindings and other non-SOAP bindings, non-HTTP SOAP
transports, `use="encoded"` (generated as literal), SOAP-encoding types and
arrays, `xsd:any` (a comment marks the spot), abstract elements/substitution
groups, `mixed` content, patterns, unresolved types/elements/groups, schemas
imported without an inline copy, notification/solicit-response operations.
WSDL 2.0 is recognized and refused.

## Postman (collection v2.0/v2.1, environment, globals)

Nested folders (description, variables, auth), requests (method, raw URL with
`{{variables}}`, query array including disabled entries, path variables
`:id` substituted or turned into `{{id}}`, headers including disabled ones),
bodies (raw by language or `Content-Type` → JSON/XML/text, urlencoded,
formdata with file parts as disabled placeholders, file bodies reported,
GraphQL), auth (noauth, inherit, basic, bearer, apikey header/query, OAuth 2
client credentials and authorization code (as PKCE); both v2.0 object and
v2.1 array parameter forms), collection/folder variables, environment and
globals exports. `protocolProfileBehavior.followRedirects`/`maxRedirects`/
`disableCookies` map to settings. Native dynamic variables (`$guid`,
`$randomUUID`, `$timestamp`, `$isoTimestamp`, `$randomInt`) are kept;
the faker family (`$randomAlphaNumeric`, …) is reported per location.

Reported: pre-request/test scripts (retained, disabled), auth types digest,
hawk, awsv4, ntlm, edgegrid, oauth1, akamai, jwt, asap (request imported with
auth `none`), OAuth 2 password/implicit grants (bearer placeholder), cached
OAuth tokens (dropped), saved example responses, per-request proxy and
certificate settings, `strictSSL: false` (inactive), disabled bodies,
collection v1 (refused).

## Insomnia (v4 JSON export, v5 YAML)

Request groups → folders (environment → folder variables, folder auth,
scripts retained), requests (URL, parameters, headers, path parameters, body
by MIME type: JSON, XML, form-urlencoded, multipart with file placeholders,
GraphQL, other text), auth (basic, bearer with prefix, API key
header/query/cookie, OAuth 2 client credentials/authorization code/refresh
token, `none`, `{}`/`inherit` → inherit), base environment → workspace
variables (nested data flattened to dotted names), sub-environments →
environments, redirect and cookie settings. Nunjucks `{{ _.name }}` becomes
`{{name}}`; `{% uuid %}` and `{% now %}` map to `{{$uuid}}`,
`{{$isoTimestamp}}`, `{{$timestamp}}`, `{{$timestampMs}}`. Path parameters
replace whole `:name` path segments by exact name (query and fragment are
untouched); literal values are percent-encoded like `encodeURIComponent`,
`{{variable}}` references are kept, and an empty value becomes a required
variable. A body MIME type the body kind cannot express (a vendor `+json`
type, `text/xml`, parameters such as `charset`) is kept as an explicit
`Content-Type` header unless the request already sets one. In a v4 export,
workspaces, request groups and environments need unique `_id`s: an export
that repeats one of those is refused, and a repeated id of any other resource
skips the later copy (`duplicate_resource_id`). A resource without an `_id`
has no children, and each workspace, group, request and environment is
imported at most once.

Reported: other template tags (`{% response %}`, `{% base64 %}`, …) and
Nunjucks filters (left in place), digest/NTLM/Hawk/IAM/netrc/ASAP auth,
cookie jars, embedded API specs, gRPC and WebSocket requests, folder-level
headers, `settingEncodeUrl: false`, disabled body rendering, private
environments (imported with a warning), unit tests (retained as scripts).

## cURL

POSIX shell tokenizing (single/double quotes, `$'…'` ANSI-C strings,
backslash escapes and line continuations, comments, a leading `$ ` prompt);
only the first command of a pipeline/list is imported. `$VAR`/`${VAR}` become
`{{VAR}}` required variables. Options: `-X`, `-H` (empty values and
`@file` reported), `-d`/`--data`/`--data-ascii`/`--data-binary`/
`--data-raw`/`--data-urlencode`/`--json`, `-F`/`--form`/`--form-string`
(file parts as placeholders), `-G`, `-I`, `-u`, `--oauth2-bearer`, `-A`, `-e`,
`-b`, `-L`, `--max-redirs`, `--compressed`, `--http1.0/1.1/2`,
`--http2-prior-knowledge`, `--http3`, `--http3-only`, `--connect-timeout`,
`-m`, `--url`, short-option clusters (`-sSL`, `-XPOST`). Method inference
follows curl (data → POST, `-G` → GET with data in the query, `-I` → HEAD).
A missing scheme defaults to `http://` (reported). Literal data keeps its
bytes, line breaks included (curl strips CR/LF only from `@file` data);
`--form-string` values are literal (no `;type=` metadata, no file reads).
SOAP requests (`SOAPAction` + XML, or `application/soap+xml`) become SOAP
bodies; a SOAP 1.2 `action` media-type parameter becomes the SOAP action.
For SOAP 1.1, the `Content-Type` is dropped only when it contains exactly
`charset=utf-8`; otherwise its explicit media type and parameters are kept.
The SOAP 1.2 `Content-Type` is dropped only when it contains exactly
`charset=utf-8` and optionally one plain `action` parameter. Otherwise the
header is kept as explicit, matching what curl sends. A bare
`application/soap+xml` header is kept as explicit.
JSON-looking data sent without a `Content-Type` stays form-typed, as curl
sends it (reported).

Reported: `-k`/`--insecure` (inactive, never applied), `--location-trusted`
(inactive), `--digest`/`--ntlm`/`--negotiate`/`--aws-sigv4`, proxies, client
certificates and CA files, `--resolve`/`--connect-to`, `-T` uploads, `@file`
data, cookie-jar files, unknown options, extra URLs. Output-only flags
(`-s`, `-v`, `-o`, …) are ignored.

## HAR 1.1/1.2

Each `http(s)` entry becomes a request grouped by host; `data:`, `blob:` and
other schemes are reported and skipped. HTTP/2 pseudo-headers and
connection headers (`Host`, `Content-Length`, …) are dropped (reported
once); cookies come from the `Cookie` header or the `cookies` array; URL
userinfo becomes Basic auth. Bodies: JSON (credential members scrubbed
recursively), form-urlencoded (from `text` or `params`), multipart `params`
(file parts as placeholders), other text verbatim with a `body_not_scanned`
warning, base64 bodies reported. A `postData.mimeType` the body kind cannot
express (a vendor `+json` type, `text/xml`, parameters) is kept as an
explicit `Content-Type` header unless one was recorded. Recorded responses,
timings and pages are not imported.

## Known limitations

* Sample payloads are produced by a constraint-aware generator, not
  validated afterwards by a full JSON Schema validator; every constraint the
  generator cannot guarantee is reported instead.
* `pattern` is never satisfied deliberately; `not`, conditionals and other
  applicators listed above are not evaluated.
* Insomnia `{{var}}` references in path-parameter values are copied verbatim,
  so the rendered value is not percent-encoded.
* Only the first `oneOf`/`anyOf` branch, the first `xsd:choice` branch and one
  media type per request body are generated.
* External references are never resolved by the importer; resolving approved
  references (and importing multi-file specs) is future work that must go
  through the explicit trust flow.
* `allowReserved` and Insomnia's "don't encode URL" cannot be represented: the
  engine always percent-encodes query values.
* Folder-level headers (Insomnia) and per-part multipart headers have no
  place in the current domain model.
* Credential redaction is name-based and best effort; arbitrary text and XML
  bodies are not scanned.
* WSDL 2.0, Postman collection v1, Insomnia design documents' embedded specs,
  gRPC/WebSocket requests from Insomnia and scripting are not supported.
* Report locations inside synthesized Swagger 2.0 `formData` schemas point at
  the originating parameter.
