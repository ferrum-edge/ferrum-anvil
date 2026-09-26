# Imports (`anvil-import`)

`crates/anvil-import` turns API descriptions and other clients' exports into
Anvil workspace objects (`Workspace`, `Folder`, `RequestDefinition`,
`Environment`) plus an `ImportReport`. It implements build plan §11 and the
import side of §12, and the failure-matrix cases DATA-008 through DATA-013.

```rust
let detected = anvil_import::detect(&bytes);             // kind + dialect, no import
let result = anvil_import::import(&bytes, &ImportOptions::default())?;
let plan = anvil_import::reimport_diff(&existing_requests, &fresh_result);
let merged = plan.apply(&existing_requests, &ReimportApproval::default());
```

Nothing is persisted or sent by the crate. The caller shows a preview (objects
plus report), lets the user choose, stores the original bytes as a
content-addressed attachment keyed by `ImportedSource::sha256`, and saves.

## Trust and safety policy

| Rule | How it is enforced |
|---|---|
| No network or file I/O during import | The crate has no I/O code paths. External `$ref`s, `wsdl:import`, `xsd:import`/`include`/`redefine` with `schemaLocation`, `externalValue` examples, OpenID Connect discovery URLs, `oauth2MetadataUrl`, Postman/Insomnia/cURL file references are listed in `report.external_refs` with every location that uses them and `requires_approval: true` (DATA-009). Resolving one is a separate, explicit, per-reference user action outside this crate. |
| Safe XML | WSDL is parsed with `roxmltree` with DTDs refused (`allow_dtd: false`): internal/external entity declarations fail the import with `ImportError::UnsafeXml`; undeclared entities are syntax errors. Node count is bounded (DATA-013). |
| Nothing becomes active by import | Pre-request/test/after-response scripts and Insomnia unit tests are copied verbatim into `report.scripts` with `enabled: false, trusted: false` and never attached to requests. TLS-verification bypass (`curl -k`, Postman `strictSSL: false`), credential forwarding across redirects (`--location-trusted`, `followAuthorizationHeader`) and OpenAPI callbacks are listed in `report.inactive_settings` and never applied (DATA-008). Imported requests are never sent. |
| No invented credentials | Auth is imported as configs whose secrets are `{{variable}}` references, listed in `report.required_variables` and deliberately *not* defined, so a request fails validation (unresolved variable) until the user supplies a value. Credential-like body fields and parameters are never generated in samples. |
| Credential redaction (migrations) | Literal credentials in HAR, cURL, Postman and Insomnia input (Authorization/Cookie/API-key-like headers, credential-like query parameters, form fields and JSON members, auth helper secrets, secret variables, cached OAuth tokens) are replaced by `{{placeholder}}` variables and listed in `report.redactions`, unless `ImportOptions::include_credentials` is set (kept values are then marked sensitive). A value that is only variable references plus an auth scheme word (`Bearer {{token}}`) is not a literal secret and is kept. Detection is name-based and best effort; bodies that cannot be scanned (XML, arbitrary text, unparsable JSON) produce a `body_not_scanned` warning. |
| Bounded work | `max_bytes` (input size), `max_nodes` (parsed JSON/YAML nodes — charged *during* deserialization, so YAML alias bombs are refused — and XML nodes), a fixed nesting-depth limit, `max_ref_depth`, `max_ref_expansions` (whole import), `max_sample_nodes` (per payload), `max_operations`. Malformed input yields an `ImportError`, never a panic (property-tested). |

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
  Insomnia, `har:<index>:<METHOD url>` for HAR and `curl:<METHOD url>` for
  cURL. Duplicates get a `#n` suffix and a warning.
* `ImportSource::generated_hash` is SHA-256 of the canonical JSON (sorted
  keys, no whitespace) of the generated `RequestSpec` with `source` removed
  (`anvil_import::spec_hash`).

## Persisting an import (`anvil-app`)

`App::spec_import` gives every import its own fresh `id_namespace` (any
namespace in the caller's options is ignored) and keeps it in the stored
source record; only a reimport of that import (`spec_reimport_plan`/`_apply`)
reuses it. Importing the same source again, into the same or another
workspace, therefore creates an independent copy and never moves or
overwrites an earlier import's requests. An import that would still overwrite
a stored object is refused.

The import is atomic: a restore checkpoint is taken first, then the new
workspace or root folder, the original bytes (a stored attachment), folders,
requests, environments and the source record are written in one
transaction. If anything fails, including taking the checkpoint, nothing is
written.

Imported into an existing workspace, the objects go under a new top-level
folder that carries the source's workspace-level scope: description,
settings, variables and auth. A source without auth of its own gets an
explicit `none` there, so imported requests resolve auth exactly as they
would in a workspace of their own and never inherit the destination
workspace's credentials. Imported environments are added to the destination
workspace.

## Reimport (DATA-012)

`reimport_diff(previous, fresh)` links requests by operation key and
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
moves added requests into the existing workspace. Changing the sample mode or
seed between imports changes generated hashes; every operation then shows up
as changed upstream.

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
at the first repeated `$ref` (`recursive_schema`), required members that
cannot be produced become `null` with a warning. `format: password`,
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
elements are annotated. Recursive types stop at the first repetition.
Credential-like elements (`password`, …) are left empty.

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
`{{$isoTimestamp}}`, `{{$timestamp}}`, `{{$timestampMs}}`.

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
A missing scheme defaults to `http://` (reported). SOAP requests
(`SOAPAction` + XML, or `application/soap+xml`) become SOAP bodies.
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
warning, base64 bodies reported. Recorded responses, timings and pages are
not imported.

## Known limitations

* Sample payloads are produced by a constraint-aware generator, not
  validated afterwards by a full JSON Schema validator; every constraint the
  generator cannot guarantee is reported instead.
* `pattern` is never satisfied deliberately; `not`, conditionals and other
  applicators listed above are not evaluated.
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
