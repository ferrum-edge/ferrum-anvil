mod common;

use anvil_domain::auth::{AuthConfig, KeyLocation, OAuthGrant};
use anvil_domain::request::{Body, MultipartContent};
use anvil_import::{Dialect, GroupBy, ImportError, ImportOptions, SampleMode, detect, import};
use common::*;
use serde_json::json;

const PETSTORE: &str = "openapi/petstore-3.0.yaml";
const ACCOUNTS: &str = "openapi/accounts-3.1.json";
const SEARCH: &str = "openapi/search-3.2.yaml";
const SWAGGER: &str = "openapi/files-swagger-2.0.json";

#[test]
fn data_011_detects_each_dialect_explicitly() {
    assert_eq!(detect(&fixture(PETSTORE)).dialect, Dialect::OpenApi30);
    assert_eq!(detect(&fixture(ACCOUNTS)).dialect, Dialect::OpenApi31);
    assert_eq!(detect(&fixture(SEARCH)).dialect, Dialect::OpenApi32);
    assert_eq!(detect(&fixture(SWAGGER)).dialect, Dialect::Swagger20);
    let r = run(SEARCH, &opts());
    assert_eq!(r.source.dialect, Dialect::OpenApi32, "3.2 must never be treated as 3.1");
    assert_eq!(r.source.declared_version.as_deref(), Some("3.2.0"));
}

#[test]
fn data_011_unknown_openapi_versions_are_refused() {
    let doc = br#"{"openapi": "4.0.0", "info": {"title": "x", "version": "1"}, "paths": {}}"#;
    assert_eq!(detect(doc).dialect, Dialect::OpenApiUnsupported);
    match import(doc, &opts()) {
        Err(ImportError::UnsupportedDialect { dialect, .. }) => assert_eq!(dialect, Dialect::OpenApiUnsupported),
        other => panic!("expected UnsupportedDialect, got {other:?}"),
    }
    let doc = br#"{"swagger": "1.2", "info": {}}"#;
    assert!(matches!(import(doc, &opts()), Err(ImportError::UnsupportedDialect { .. })));
}

#[test]
fn petstore_servers_become_environments() {
    let r = run(PETSTORE, &opts());
    assert_eq!(r.workspace.name, "Petstore 1.4.0");
    assert_eq!(r.environments.len(), 2);
    let prod = &r.environments[0];
    assert_eq!(prod.name, "Production");
    let var = |n: &str| prod.variables.iter().find(|v| v.name == n).map(|v| v.value.clone());
    assert_eq!(
        var("baseUrl"),
        Some(anvil_domain::secret::SensitiveValue::template("https://{{region}}.petstore.example.com/{{basePath}}"))
    );
    assert_eq!(var("region"), Some(anvil_domain::secret::SensitiveValue::template("eu")));
    assert!(prod.variables.iter().any(|v| v.name == "region" && v.description.contains("eu, us")));
    assert_eq!(r.workspace.active_environment_id, Some(prod.meta.id));
    // server_index selects the active environment.
    let r2 = run(PETSTORE, &ImportOptions { server_index: 1, ..opts() });
    assert_eq!(r2.workspace.active_environment_id, Some(r2.environments[1].meta.id));
    let r3 = run(PETSTORE, &ImportOptions { server_index: 9, ..opts() });
    assert!(has(&r3, "server_index_out_of_range"));
}

#[test]
fn petstore_parameters_and_styles() {
    let r = run(PETSTORE, &opts());
    let list = &req(&r, "listPets").spec;
    assert_eq!(list.url, "{{baseUrl}}/pets");
    assert_eq!(list.method, "GET");
    // Optional parameter: present but disabled unless include_optional.
    let limit = param(list, "limit").unwrap();
    assert!(!limit.enabled);
    assert_eq!(limit.value, "20", "default is used in sample mode");
    // form + explode=false array.
    assert_eq!(param(list, "status").unwrap().value, "available");
    // deepObject.
    assert_eq!(param(list, "filter[color]").unwrap().value, "brown");
    // Header with uuid format.
    let rid = header(list, "X-Request-ID").unwrap();
    assert!(uuid::Uuid::parse_str(&rid.value).is_ok());
    // Required cookie enabled; optional cookie only in the disabled variant.
    let cookies: Vec<_> = list.headers.iter().filter(|h| h.name == "Cookie").collect();
    assert_eq!(cookies[0].value, "locale=en-GB");
    assert!(cookies[0].enabled);
    assert_eq!(cookies[1].value, "locale=en-GB; theme=dark");
    assert!(!cookies[1].enabled);
    assert_eq!(header(list, "Accept").unwrap().value, "application/json");

    // Path-level $ref parameter with example; label style.
    assert_eq!(req(&r, "getPet").spec.url, "{{baseUrl}}/pets/42");
    assert_eq!(req(&r, "petLabel").spec.url, "{{baseUrl}}/pets/42/label.png,large");

    // include_optional enables optional params.
    let r2 = run(PETSTORE, &ImportOptions { include_optional: true, ..opts() });
    let list2 = &req(&r2, "listPets").spec;
    assert!(param(list2, "limit").unwrap().enabled);
    assert_eq!(list2.headers.iter().filter(|h| h.name == "Cookie").count(), 1);
}

#[test]
fn petstore_bodies() {
    let r = run(PETSTORE, &opts());
    // allOf + readOnly + writeOnly credential.
    let create = json_body(&req(&r, "createPet").spec);
    assert_eq!(create, json!({"name": "Rex", "category": {"name": "dogs"}, "password": ""}));
    assert!(create.get("id").is_none(), "readOnly members are omitted from requests");
    assert!(has_at(&r, "credential_left_blank", "/components/schemas/NewPet/properties/password"));
    // JSON preferred over XML, alternatives reported.
    assert!(matches!(req(&r, "updatePet").spec.body, Body::Json { .. }));
    assert!(has_at(&r, "alternative_media_types", "/put/requestBody/content"));
    // XML with xml hints (attribute, wrapped array) when include_optional.
    let r2 = run(PETSTORE, &ImportOptions { include_optional: true, ..opts() });
    match &req(&r2, "replacePetXml").spec.body {
        Body::Xml { text } => {
            let doc = roxmltree::Document::parse(text).expect("generated XML is well-formed");
            let root = doc.root_element();
            assert_eq!(root.tag_name().name(), "pet");
            assert_eq!(root.attribute("kind"), Some("dog"));
            let wrapper = root.children().find(|c| c.has_tag_name("photoUrls")).expect("wrapped array");
            assert!(wrapper.children().any(|c| c.has_tag_name("photoUrl")));
            assert!(root.children().all(|c| !c.has_tag_name("id")), "readOnly id omitted");
        }
        other => panic!("expected XML, got {other:?}"),
    }
    // Multipart: file part disabled placeholder, content type from encoding.
    match &req(&r, "uploadPhoto").spec.body {
        Body::Multipart { parts } => {
            let file = parts.iter().find(|p| p.name == "file").unwrap();
            assert!(!file.enabled);
            assert_eq!(file.content_type.as_deref(), Some("image/png"));
            let caption = parts.iter().find(|p| p.name == "caption").unwrap();
            match &caption.content {
                MultipartContent::Text { value } => assert!(!value.is_empty() && value.len() <= 40),
                other => panic!("{other:?}"),
            }
        }
        other => panic!("expected multipart, got {other:?}"),
    }
    assert!(has(&r, "file_part_requires_attachment"));
    // Form: minItems/maxItems honored, ranges honored.
    match &req(&r, "placeOrder").spec.body {
        Body::FormUrlEncoded { fields } => {
            assert_eq!(fields.iter().filter(|f| f.name == "tags").count(), 2);
            let q: i64 = fields.iter().find(|f| f.name == "quantity").unwrap().value.parse().unwrap();
            assert!((1..=5).contains(&q));
        }
        other => panic!("expected form, got {other:?}"),
    }
}

#[test]
fn recursion_composition_and_contradictions_are_reported() {
    let r = run(PETSTORE, &opts());
    let tree = json_body(&req(&r, "postTree").spec);
    assert!(tree["value"].is_string());
    assert_eq!(tree["children"], json!([]), "recursion is cut, not looped");
    assert!(has_at(&r, "recursive_schema", "/components/schemas/TreeNode"));
    let shape = json_body(&req(&r, "postShape").spec);
    assert_eq!(shape["shapeType"], "circle", "discriminator mapping value is set");
    let radius = shape["radius"].as_f64().unwrap();
    assert!(radius > 0.0 && radius <= 10.0, "exclusiveMinimum honored: {radius}");
    assert!(has_at(&r, "composition_first_branch", "/components/schemas/Shape/oneOf"));
    assert!(has_at(&r, "contradictory_schema", "/paths/~1contradiction/post/requestBody/content/application~1json/schema/properties/n"));
    assert!(has_at(&r, "contradictory_schema", "/properties/s"));
}

#[test]
fn data_009_external_refs_are_reported_never_fetched() {
    let r = run(PETSTORE, &opts());
    let ext = &r.report.external_refs;
    assert_eq!(ext.len(), 1);
    assert_eq!(ext[0].reference, "common/schemas.yaml#/Widget");
    assert!(ext[0].requires_approval);
    assert_eq!(ext[0].kind, anvil_import::ExternalRefKind::File);
    assert_eq!(ext[0].pointers, vec!["/paths/~1external/post/requestBody/content/application~1json/schema".to_string()]);
    assert_eq!(json_body(&req(&r, "postExternal").spec), json!({}));

    // URL refs, internal metadata endpoints: listed, not resolved.
    let doc = json!({
        "openapi": "3.0.3", "info": {"title": "t", "version": "1"},
        "paths": {"/a": {"post": {"operationId": "a", "requestBody": {"content": {"application/json": {"schema": {"$ref": "http://169.254.169.254/latest/meta-data/iam#/x"}}}}, "responses": {}}}}
    });
    let r = import(doc.to_string().as_bytes(), &opts()).unwrap();
    assert_eq!(r.report.external_refs[0].kind, anvil_import::ExternalRefKind::Url);
}

#[test]
fn security_schemes_become_placeholders() {
    let r = run(PETSTORE, &opts());
    // Global security → workspace auth; operations inherit.
    match &r.workspace.auth {
        AuthConfig::ApiKey { name, value, location } => {
            assert_eq!(name, "X-API-Key");
            assert_eq!(*location, KeyLocation::Header);
            assert!(value.is_pure_reference());
        }
        other => panic!("{other:?}"),
    }
    assert_eq!(req(&r, "listPets").spec.auth, AuthConfig::Inherit);
    assert_eq!(req(&r, "getPet").spec.auth, AuthConfig::None, "security: [] disables auth");
    match &req(&r, "createPet").spec.auth {
        AuthConfig::OAuth2 { config } => {
            assert_eq!(config.grant, OAuthGrant::ClientCredentials);
            assert_eq!(config.token_url, "https://auth.petstore.example.com/token");
            assert_eq!(config.scope, "write:pets read:pets");
            assert_eq!(config.client_id, "{{petstore_auth_client_id}}");
            assert!(config.client_secret.is_pure_reference());
        }
        other => panic!("{other:?}"),
    }
    match &req(&r, "deletePet").spec.auth {
        AuthConfig::Multi { profiles } => {
            assert!(matches!(profiles[0], AuthConfig::Basic { .. }));
            assert!(matches!(profiles[1], AuthConfig::ApiKey { .. }));
        }
        other => panic!("{other:?}"),
    }
    // Credential-like parameters are placeholders, never generated.
    let key = header(&req(&r, "deletePet").spec, "api_key").unwrap();
    assert_eq!(key.value, "{{api_key}}");
    assert!(key.sensitive);
    let names: Vec<&str> = r.report.required_variables.iter().map(|v| v.name.as_str()).collect();
    for n in ["api_key", "petstore_auth_client_id", "petstore_auth_client_secret", "basicAuth_username", "basicAuth_password"] {
        assert!(names.contains(&n), "missing required variable {n}: {names:?}");
    }
    assert!(r.report.required_variables.iter().find(|v| v.name == "basicAuth_password").unwrap().secret);
    // Nothing defines those variables (no invented credentials).
    for env in &r.environments {
        assert!(env.variables.iter().all(|v| !names.contains(&v.name.as_str()) || v.name == "baseUrl"));
    }
}

#[test]
fn callbacks_are_inactive() {
    let r = run(PETSTORE, &opts());
    let cb = r.report.inactive_settings.iter().find(|s| s.setting == "callback").expect("callback reported");
    assert_eq!(cb.pointer, "/paths/~1pets/post/callbacks/onAdopted");
    assert!(r.requests.iter().all(|q| !q.spec.url.contains("callbackUrl")));
}

#[test]
fn grouping_by_tags_and_paths() {
    let r = run(PETSTORE, &opts());
    let names: Vec<(&str, f64)> = r.folders.iter().map(|f| (f.name.as_str(), f.sort_key)).collect();
    // Declared tag order (store before pets) wins over first use.
    let store = names.iter().find(|n| n.0 == "store").unwrap().1;
    let pets = names.iter().find(|n| n.0 == "pets").unwrap().1;
    assert!(store < pets);
    assert_eq!(r.folders.iter().find(|f| f.name == "pets").unwrap().description, "Everything about pets");
    assert!(req(&r, "postTree").folder_id.is_none(), "untagged operations stay at the top level");
    let r2 = run(PETSTORE, &ImportOptions { group_by: GroupBy::Paths, ..opts() });
    let folder_names: Vec<&str> = r2.folders.iter().map(|f| f.name.as_str()).collect();
    assert_eq!(folder_names, vec!["pets", "store", "tree", "shapes", "external", "contradiction"]);
}

#[test]
fn operation_keys_and_generated_hashes() {
    let r = run(PETSTORE, &opts());
    for q in &r.requests {
        let s = q.spec.source.as_ref().unwrap();
        assert_eq!(s.import_id, r.source.import_id);
        assert_eq!(s.generated_hash, anvil_import::spec_hash(&q.spec));
    }
    // No operationId → METHOD path.
    let doc = br#"{"openapi":"3.0.0","info":{"title":"t","version":"1"},"paths":{"/x/{id}":{"get":{"responses":{}},"post":{"operationId":"dup","responses":{}}},"/y":{"put":{"operationId":"dup","responses":{}}}}}"#;
    let r = import(doc, &opts()).unwrap();
    assert_eq!(keys(&r), vec!["GET /x/{id}", "dup", "dup#2"]);
    assert!(has(&r, "duplicate_operation_key"));
    assert!(has(&r, "undeclared_path_parameter"));
}

#[test]
fn data_010_blank_mode_is_structural_and_never_uses_examples() {
    let o = ImportOptions { mode: SampleMode::Blank, ..opts() };
    let r = run(PETSTORE, &o);
    assert_eq!(json_body(&req(&r, "createPet").spec), json!({"name": "", "category": {"name": ""}, "password": ""}));
    assert_eq!(req(&r, "getPet").spec.url, "{{baseUrl}}/pets/{{petId}}");
    assert!(r.report.required_variables.iter().any(|v| v.name == "petId" && !v.secret));
    let list = &req(&r, "listPets").spec;
    assert_eq!(param(list, "status").unwrap().value, "");
    assert_eq!(param(list, "limit").unwrap().value, "");
    assert_eq!(json_body(&req(&r, "postShape").spec)["radius"], json!(0));
    // Sample and blank differ, and blank ids differ (options are part of the namespace).
    let s = run(PETSTORE, &opts());
    assert_ne!(s.requests[0].meta.id, r.requests[0].meta.id);
}

#[test]
fn openapi_31_constructs() {
    let r = run(ACCOUNTS, &opts());
    // Relative server URL → {{origin}} placeholder.
    assert_eq!(r.environments[0].variables[0].value, anvil_domain::secret::SensitiveValue::template("{{origin}}/api"));
    assert!(r.report.required_variables.iter().any(|v| v.name == "origin"));
    assert!(has(&r, "json_schema_dialect"));
    // Media-type example via components/examples $ref; vendor JSON keeps its Content-Type.
    let create = &req(&r, "createAccount").spec;
    assert_eq!(json_body(create), json!({"name": "Ada", "nickname": null, "tier": "gold"}));
    assert_eq!(header(create, "Content-Type").unwrap().value, "application/vnd.accounts+json");
    // Path item $ref, type arrays, prefixItems, $ref sibling default.
    let patch = &req(&r, "patchAccount").spec;
    let body = json_body(patch);
    assert!(body["nickname"].as_str().unwrap().len() <= 12);
    assert_eq!(body["limits"][1], "daily");
    let first = body["limits"][0].as_i64().unwrap();
    assert!((1..=5).contains(&first), "exclusiveMinimum 0 / maximum 5: {first}");
    assert_eq!(body["tier"], "silver");
    assert!(uuid::Uuid::parse_str(patch.url.trim_start_matches("{{baseUrl}}/accounts/")).is_ok());
    // Query styles.
    let list = &req(&r, "listAccounts").spec;
    assert_eq!(param(list, "ids").unwrap().value, "1|2|3");
    assert_eq!(param(list, "tags").unwrap().value, "vip");
    assert_eq!(param(list, "filter").unwrap().value, r#"{"active":true}"#);
    assert_eq!(param(list, "access_token").unwrap().value, "{{access_token}}");
    // Security alternatives: mutualTLS unsupported → bearer chosen, both reported.
    assert!(matches!(list.auth, AuthConfig::Bearer { .. }));
    assert!(has(&r, "security_alternatives"));
    assert!(has_at(&r, "mutual_tls_scheme", "/components/securitySchemes/mtls"));
    assert!(has_at(&r, "webhook_not_imported", "/webhooks/accountClosed"));
    // Not a false positive for 3.1 type arrays.
    assert!(!has(&r, "type_array_in_legacy_dialect"));
}

#[test]
fn openapi_32_constructs() {
    let r = run(SEARCH, &opts());
    // QUERY and additionalOperations methods.
    assert_eq!(req(&r, "queryItems").spec.method, "QUERY");
    assert_eq!(json_body(&req(&r, "queryItems").spec), json!({"text": "lamp"}), "example dataValue");
    assert_eq!(req(&r, "linkItems").spec.method, "LINK");
    // querystring parameter; cookie style.
    let items = &req(&r, "getItems").spec;
    assert_eq!(param(items, "term").unwrap().value, "desk");
    assert_eq!(param(items, "page").unwrap().value, "2");
    assert_eq!(header(items, "Cookie").unwrap().value, "prefs=compact");
    // Hierarchical tags → nested folders.
    let catalog = r.folders.iter().find(|f| f.name == "catalog").unwrap();
    let items_f = r.folders.iter().find(|f| f.name == "items").unwrap();
    assert_eq!(items_f.parent_id, Some(catalog.meta.id));
    assert_eq!(catalog.description, "Catalog operations");
    // Server name.
    assert_eq!(r.environments[0].name, "prod");
    // XML nodeType attribute/cdata.
    match &req(&r, "xmlItem").spec.body {
        Body::Xml { text } => {
            let doc = roxmltree::Document::parse(text).unwrap();
            assert_eq!(doc.root_element().attribute("id"), Some("7"));
            assert!(text.contains("<![CDATA[a < b]]>"));
        }
        other => panic!("{other:?}"),
    }
    // Matrix explode.
    assert_eq!(req(&r, "getItem").spec.url, "{{baseUrl}}/items/;id=1;id=2");
    // Unsupported 3.2 constructs are reported, not ignored.
    assert!(has_at(&r, "item_schema_stream", "/itemSchema"));
    assert!(has_at(&r, "self_base_uri", "/$self"));
    assert!(has_at(&r, "oauth2_flow_unsupported", "/components/securitySchemes/device"));
    assert!(r.report.external_refs.iter().any(|e| e.reference.contains(".well-known/oauth-authorization-server")));
}

#[test]
fn openapi_32_constructs_in_31_documents_are_warned() {
    let doc = json!({
        "openapi": "3.1.1", "info": {"title": "t", "version": "1"},
        "tags": [{"name": "a", "parent": "b"}],
        "paths": {"/x": {
            "query": {"operationId": "q", "responses": {}},
            "additionalOperations": {"LINK": {"operationId": "l", "responses": {}}},
            "get": {"operationId": "g", "parameters": [{"name": "qs", "in": "querystring", "content": {"application/x-www-form-urlencoded": {"schema": {"type": "object"}}}}], "responses": {}}
        }}
    });
    let r = import(doc.to_string().as_bytes(), &opts()).unwrap();
    assert_eq!(keys(&r), vec!["g"], "3.2-only operations are not imported from a 3.1 document");
    let warned: Vec<&str> = r.report.warnings.iter().filter(|w| w.code == "openapi32_construct").map(|w| w.pointer.as_str()).collect();
    assert!(warned.contains(&"/paths/~1x/query"));
    assert!(warned.contains(&"/paths/~1x/additionalOperations"));
    assert!(warned.contains(&"/tags/0/parent"));
    assert!(warned.contains(&"/paths/~1x/get/parameters/0"));
}

#[test]
fn swagger_20() {
    let r = run(SWAGGER, &opts());
    assert_eq!(r.environments.len(), 2);
    assert_eq!(r.environments[0].variables[0].value, anvil_domain::secret::SensitiveValue::template("https://files.example.com/v2"));
    // Global basic auth.
    assert!(matches!(r.workspace.auth, AuthConfig::Basic { .. }));
    // formData + file → multipart; collectionFormat multi → repeated parts.
    let up = &req(&r, "uploadFile").spec;
    assert_eq!(up.url, "{{baseUrl}}/folders/reports/files", "x-example on a path parameter");
    match &up.body {
        Body::Multipart { parts } => {
            assert!(!parts.iter().find(|p| p.name == "file").unwrap().enabled);
            assert!(parts.iter().any(|p| p.name == "note"));
            assert!(parts.iter().any(|p| p.name == "labels"));
        }
        other => panic!("{other:?}"),
    }
    assert!(has_at(&r, "file_part_requires_attachment", "/paths/~1folders~1{folder}~1files/post/parameters/0"));
    match &up.auth {
        AuthConfig::OAuth2 { config } => {
            assert_eq!(config.grant, OAuthGrant::AuthorizationCodePkce);
            assert_eq!(config.authorization_url, "https://auth.files.example.com/authorize");
            assert_eq!(config.scope, "files:write");
        }
        other => panic!("{other:?}"),
    }
    // collectionFormat pipes / csv; apiKey in query.
    let list = &req(&r, "listFiles").spec;
    let sizes = &param(list, "sizes").unwrap().value;
    assert_eq!(sizes.split('|').count(), 2, "{sizes}");
    assert_eq!(param(list, "kinds").unwrap().value, "pdf");
    assert!(matches!(&list.auth, AuthConfig::ApiKey { location: KeyLocation::Query, name, .. } if name == "api_key"));
    // body parameter with schema example; x-nullable.
    assert_eq!(json_body(&req(&r, "putMetadata").spec)["title"], "Q3 report");
    // urlencoded formData with a password never generated.
    match &req(&r, "login").spec.body {
        Body::FormUrlEncoded { fields } => assert_eq!(fields.iter().find(|f| f.name == "password").unwrap().value, ""),
        other => panic!("{other:?}"),
    }
    assert_eq!(req(&r, "login").spec.auth, AuthConfig::None);
}

#[test]
fn deterministic_for_same_input_and_seed() {
    for f in [PETSTORE, ACCOUNTS, SEARCH, SWAGGER] {
        let a = run(f, &opts());
        let b = run(f, &opts());
        assert_eq!(a, b, "{f} import is not deterministic");
        let c = run(f, &ImportOptions { seed: 99, ..opts() });
        assert_eq!(a.source.sha256, c.source.sha256);
    }
    let a = run(PETSTORE, &opts());
    let c = run(PETSTORE, &ImportOptions { seed: 99, ..opts() });
    assert_ne!(json_body(&req(&a, "postTree").spec), json_body(&req(&c, "postTree").spec), "seed changes generated values");
}

#[test]
fn samples_are_stable_per_operation() {
    // Adding an operation does not change the samples of the others.
    let base = String::from_utf8(fixture(PETSTORE)).unwrap();
    let extended = base.replace(
        "  /tree:\n",
        "  /zzz:\n    post:\n      operationId: extra\n      requestBody:\n        content:\n          application/json:\n            schema: { type: object, required: [a], properties: { a: { type: string } } }\n      responses:\n        '200': { description: ok }\n  /tree:\n",
    );
    let a = import(base.as_bytes(), &opts()).unwrap();
    let b = import(extended.as_bytes(), &opts()).unwrap();
    assert_eq!(req(&a, "postTree").spec, {
        let mut s = req(&b, "postTree").spec.clone();
        s.source = req(&a, "postTree").spec.source.clone();
        s
    });
}

#[test]
fn operation_limit_is_enforced_and_reported() {
    let r = run(PETSTORE, &ImportOptions { max_operations: 3, ..opts() });
    assert_eq!(r.requests.len(), 3);
    assert_eq!(r.report.counts.skipped_operations, r.report.counts.operations_found - 3);
    assert!(has(&r, "operation_limit"));
}

#[test]
fn ref_budget_and_depth_are_bounded() {
    // A long $ref chain and a wide fan-out of refs.
    let mut schemas = serde_json::Map::new();
    for i in 0..200 {
        schemas.insert(format!("S{i}"), json!({"$ref": format!("#/components/schemas/S{}", i + 1)}));
    }
    schemas.insert("S200".into(), json!({"type": "string"}));
    let doc = json!({
        "openapi": "3.0.0", "info": {"title": "t", "version": "1"},
        "paths": {"/a": {"post": {"operationId": "a", "requestBody": {"content": {"application/json": {"schema": {"$ref": "#/components/schemas/S0"}}}}, "responses": {}}}},
        "components": {"schemas": schemas}
    });
    let r = import(doc.to_string().as_bytes(), &ImportOptions { max_ref_depth: 16, ..opts() }).unwrap();
    assert!(has(&r, "ref_depth_limit"));
    let r = import(doc.to_string().as_bytes(), &ImportOptions { max_ref_expansions: 10, max_ref_depth: 1000, ..opts() }).unwrap();
    assert!(has(&r, "ref_budget_exhausted"));
}

/// One POST operation whose JSON request body is `#/components/schemas/{root}`.
fn doc_with_schemas(schemas: serde_json::Map<String, serde_json::Value>, root: &str) -> Vec<u8> {
    let body = json!({"content": {"application/json": {"schema": {"$ref": format!("#/components/schemas/{root}")}}}});
    let doc = json!({
        "openapi": "3.0.0", "info": {"title": "t", "version": "1"},
        "paths": {"/a": {"post": {"operationId": "a", "requestBody": body, "responses": {}}}},
        "components": {"schemas": schemas}
    });
    doc.to_string().into_bytes()
}

#[test]
fn long_all_of_chains_stop_at_the_ref_depth() {
    // Each schema only composes the next one, so every `$ref` is one hop.
    let mut schemas = serde_json::Map::new();
    for i in 0..200 {
        let p = format!("p{i}");
        let next = format!("#/components/schemas/A{}", i + 1);
        let mut props = serde_json::Map::new();
        props.insert(p.clone(), json!({"type": "string"}));
        schemas.insert(format!("A{i}"), json!({"allOf": [{"$ref": next}], "type": "object", "required": [p], "properties": props}));
    }
    schemas.insert("A200".into(), json!({"type": "object"}));
    let r = import(&doc_with_schemas(schemas, "A0"), &opts()).unwrap();
    assert!(has(&r, "ref_depth_limit"));
    let body = json_body(&req(&r, "a").spec);
    assert!(body.get("p0").is_some() && body.get("p1").is_some(), "{body}");
    assert!(body.get("p100").is_none() && body.get("p199").is_none(), "{body}");
}

#[test]
fn branching_all_of_graphs_hit_the_sample_budget() {
    // Each schema composes the next one twice: 2^17 merges without a budget.
    let mut schemas = serde_json::Map::new();
    for i in 0..16 {
        let next = json!({"$ref": format!("#/components/schemas/D{}", i + 1)});
        schemas.insert(format!("D{i}"), json!({"allOf": [next.clone(), next]}));
    }
    schemas.insert("D16".into(), json!({"type": "object", "required": ["leaf"], "properties": {"leaf": {"type": "string"}}}));
    let r = import(&doc_with_schemas(schemas.clone(), "D0"), &opts()).unwrap();
    assert!(has(&r, "sample_size_limit"));
    assert_eq!(r.requests.len(), 1);
    // A small diamond still merges completely.
    let r = import(&doc_with_schemas(schemas, "D13"), &opts()).unwrap();
    assert!(!has(&r, "sample_size_limit"));
    assert!(!has(&r, "ref_depth_limit"));
    assert_eq!(json_body(&req(&r, "a").spec).get("leaf").map(|v| v.is_string()), Some(true));
}

#[test]
fn copied_examples_share_an_import_byte_budget() {
    // One 1 MB example referenced by 100 members of each of three payloads.
    let mut schemas = serde_json::Map::new();
    schemas.insert("Big".into(), json!({"type": "string", "example": "x".repeat(1024 * 1024)}));
    let mut props = serde_json::Map::new();
    for i in 0..100 {
        props.insert(format!("p{i}"), json!({"$ref": "#/components/schemas/Big"}));
    }
    let names: Vec<String> = (0..100).map(|i| format!("p{i}")).collect();
    schemas.insert("Root".into(), json!({"type": "object", "required": names, "properties": props}));
    let body = json!({"content": {"application/json": {"schema": {"$ref": "#/components/schemas/Root"}}}});
    let op = |id: &str| json!({"operationId": id, "requestBody": body.clone(), "responses": {}});
    let doc = json!({
        "openapi": "3.0.0", "info": {"title": "t", "version": "1"},
        "paths": {"/a": {"post": op("a"), "put": op("b"), "patch": op("c")}},
        "components": {"schemas": schemas}
    });
    // A 4 MiB input limit allows 32 MiB of copies for the whole import.
    let r = import(doc.to_string().as_bytes(), &ImportOptions { max_bytes: 4 * 1024 * 1024, ..opts() }).unwrap();
    assert!(has(&r, "sample_size_limit"));
    let total: usize = r.requests.iter().map(|q| serde_json::to_string(&q.spec.body).map_or(0, |t| t.len())).sum();
    assert!(total < 40 * 1024 * 1024, "the bodies hold {total} bytes");
    assert_eq!(r.requests.len(), 3);
}

/// `Root` has `n` required members, each `member`; `ops` operations send it
/// as `media`.
fn wide_doc(n: usize, member: serde_json::Value, extra: serde_json::Map<String, serde_json::Value>, media: &str, ops: usize) -> Vec<u8> {
    let mut props = serde_json::Map::new();
    for i in 0..n {
        props.insert(format!("p{i}"), member.clone());
    }
    let names: Vec<String> = (0..n).map(|i| format!("p{i}")).collect();
    let mut schemas = extra;
    schemas.insert("Root".into(), json!({"type": "object", "required": names, "properties": props}));
    let mut paths = serde_json::Map::new();
    for i in 0..ops {
        let body = json!({"content": {media: {"schema": {"$ref": "#/components/schemas/Root"}}}});
        paths.insert(format!("/op{i}"), json!({"post": {"operationId": format!("op{i}"), "requestBody": body, "responses": {}}}));
    }
    let doc = json!({"openapi": "3.0.0", "info": {"title": "t", "version": "1"}, "paths": paths, "components": {"schemas": schemas}});
    doc.to_string().into_bytes()
}

#[test]
fn structural_lookups_share_one_budget_per_payload() {
    // The XML writer looks up every member's schema twice; each is an allOf
    // of 20k branches, so a fresh budget per lookup would redo that work for
    // all 20k members.
    let mut extra = serde_json::Map::new();
    let branches = vec![json!({}); 20_000];
    extra.insert("X".into(), json!({"allOf": branches}));
    let doc = wide_doc(20_000, json!({"$ref": "#/components/schemas/X"}), extra, "application/xml", 1);
    let r = import(&doc, &opts()).unwrap();
    assert!(has(&r, "sample_size_limit"));
    match &req(&r, "op0").spec.body {
        Body::Xml { text } => assert!(text.len() < 4 * 1024 * 1024, "the body is {} bytes", text.len()),
        other => panic!("expected an XML body, got {other:?}"),
    }
}

#[test]
fn generated_strings_share_the_import_byte_budget() {
    // 20k members padded to 4096 characters, in ten operations: about 800 MB
    // without a byte budget. A 4 MiB input limit allows 16 MiB for the import.
    let doc = wide_doc(20_000, json!({"type": "string", "minLength": 4096}), serde_json::Map::new(), "application/json", 10);
    let r = import(&doc, &ImportOptions { max_bytes: 4 * 1024 * 1024, ..opts() }).unwrap();
    assert!(has(&r, "sample_size_limit"));
    assert_eq!(r.requests.len(), 10);
    let total: usize = r.requests.iter().map(|q| serde_json::to_string(&q.spec.body).map_or(0, |t| t.len())).sum();
    assert!(total < 20 * 1024 * 1024, "the bodies hold {total} bytes");
}

#[test]
fn wide_schemas_hit_the_sample_budget() {
    let mut props = serde_json::Map::new();
    let mut req_names = vec![];
    for i in 0..500 {
        props.insert(format!("p{i}"), json!({"type": "object", "required": ["x"], "properties": {"x": {"type": "array", "minItems": 20, "items": {"type": "string"}}}}));
        req_names.push(json!(format!("p{i}")));
    }
    let doc = json!({
        "openapi": "3.0.0", "info": {"title": "t", "version": "1"},
        "paths": {"/a": {"post": {"operationId": "a", "requestBody": {"content": {"application/json": {"schema": {"type": "object", "required": req_names, "properties": props}}}}, "responses": {}}}}
    });
    let r = import(doc.to_string().as_bytes(), &ImportOptions { max_sample_nodes: 1000, ..opts() }).unwrap();
    assert!(has(&r, "sample_size_limit"));
}

#[test]
fn input_size_limit() {
    let r = import(&fixture(PETSTORE), &ImportOptions { max_bytes: 100, ..opts() });
    assert!(matches!(r, Err(ImportError::TooLarge { .. })));
    let r = import(&fixture(PETSTORE), &ImportOptions { max_nodes: 50, ..opts() });
    assert!(matches!(r, Err(ImportError::LimitExceeded { .. })));
}

/// A JSON body of 32 × 32 × 32 copies of `#/components/schemas/X`: about
/// 20k visits of `X` within the default payload budget.
fn repeated_doc(x: serde_json::Value) -> Vec<u8> {
    let mut schema = json!({"$ref": "#/components/schemas/X"});
    for _ in 0..3 {
        schema = json!({"type": "array", "minItems": 32, "items": schema});
    }
    let mut schemas = serde_json::Map::new();
    schemas.insert("X".into(), x);
    schemas.insert("Root".into(), schema);
    doc_with_schemas(schemas, "Root")
}

fn count_leaves(v: &serde_json::Value) -> usize {
    match v {
        serde_json::Value::Array(a) => a.iter().map(count_leaves).sum(),
        serde_json::Value::Object(o) => o.values().map(count_leaves).sum(),
        _ => 1,
    }
}

fn count_nulls(v: &serde_json::Value) -> usize {
    match v {
        serde_json::Value::Null => 1,
        serde_json::Value::Array(a) => a.iter().map(count_nulls).sum(),
        serde_json::Value::Object(o) => o.values().map(count_nulls).sum(),
        _ => 0,
    }
}

#[test]
fn wide_objects_charge_every_member_looked_at() {
    // 60k optional members, each a `$ref`, and 60k required names none of
    // them declares: every member used to be resolved and compared with
    // every name (3.6e9 comparisons) before being skipped.
    let mut props = serde_json::Map::new();
    for i in 0..60_000 {
        props.insert(format!("o{i}"), json!({"$ref": "#/components/schemas/Leaf"}));
    }
    let names: Vec<String> = (0..60_000).map(|i| format!("r{i}")).collect();
    let mut schemas = serde_json::Map::new();
    schemas.insert("Leaf".into(), json!({"type": "string"}));
    schemas.insert("Root".into(), json!({"type": "object", "required": names, "properties": props}));
    let r = import(&doc_with_schemas(schemas, "Root"), &opts()).unwrap();
    // Skipped members are not resolved: only the body's own `$ref` is.
    assert!(r.report.counts.refs_resolved < 10, "{} $refs resolved", r.report.counts.refs_resolved);
    let body = json_body(&req(&r, "a").spec);
    let members = body.as_object().expect("an object body");
    assert!(members.keys().all(|k| k.starts_with('r')), "optional members were generated");
    // Each undeclared name's null is charged, so the payload budget holds.
    assert!(members.len() <= opts().max_sample_nodes, "{} members", members.len());
    assert!(has(&r, "sample_size_limit"));
}

#[test]
fn nulls_for_undeclared_required_names_are_charged() {
    // `X` requires 10k names it never declares, and the body repeats it about
    // 20k times: 2e8 nulls when they were not charged.
    let names: Vec<String> = (0..10_000).map(|i| format!("u{i}")).collect();
    let r = import(&repeated_doc(json!({"type": "object", "required": names})), &opts()).unwrap();
    assert!(has(&r, "sample_size_limit"));
    let nulls = count_nulls(&json_body(&req(&r, "a").spec));
    assert!((1..=opts().max_sample_nodes).contains(&nulls), "{nulls} nulls");
}

#[test]
fn enum_and_const_scans_are_charged() {
    // Each visit of `X` scans 200k `enum` values for the first non-null one,
    // or compares `const` with 500k `enum` values; the body visits `X` about
    // 20k times, which the payload's node budget allows. The scans are
    // charged to the byte budget, so a 4 MiB input limit (16 MiB for the
    // import) stops them after a few visits: far fewer values are generated.
    let mut values = vec![serde_json::Value::Null; 200_000];
    values.push(json!("a"));
    let o = ImportOptions { max_bytes: 4 * 1024 * 1024, ..opts() };
    for x in [json!({"enum": values}), json!({"const": 0, "enum": vec![1; 500_000]})] {
        let r = import(&repeated_doc(x), &o).unwrap();
        assert!(has(&r, "sample_size_limit"));
        assert_eq!(r.requests.len(), 1);
        let values = count_leaves(&json_body(&req(&r, "a").spec));
        assert!(values < 1_000, "{values} values generated");
    }
}

#[test]
fn const_with_an_empty_enum_is_not_walked() {
    // `const` is a 400k-item array and `enum` is empty: each of about 20k
    // visits used to walk all of `const` (uncharged, since the charge is its
    // size times the enum's length) before copying the small example.
    let x = json!({"example": 1, "const": vec![0; 400_000], "enum": []});
    let r = import(&repeated_doc(x), &opts()).unwrap();
    assert!(has(&r, "contradictory_schema"));
    let values = count_leaves(&json_body(&req(&r, "a").spec));
    assert!(values > 1_000, "{values} values generated");
}

#[test]
fn structural_lookups_borrow_what_they_do_not_merge() {
    // 40 attributes whose schema carries a 200 KB description. Copying it for
    // every lookup spent a 1 MiB input's 4 MiB byte budget in the first
    // payload and lost the attribute hints.
    let mut extra = serde_json::Map::new();
    let leaf = json!({"type": "string", "description": "x".repeat(200 * 1024), "xml": {"attribute": true}});
    extra.insert("Leaf".into(), leaf);
    let doc = wide_doc(40, json!({"$ref": "#/components/schemas/Leaf"}), extra, "application/xml", 2);
    let r = import(&doc, &ImportOptions { max_bytes: 1024 * 1024, ..opts() }).unwrap();
    assert!(!has(&r, "sample_size_limit"));
    for op in ["op0", "op1"] {
        match &req(&r, op).spec.body {
            Body::Xml { text } => assert!(text.contains(" p0=\"") && text.contains(" p39=\""), "{text}"),
            other => panic!("expected an XML body, got {other:?}"),
        }
    }
}

#[test]
fn long_pointers_and_refs_are_charged_and_clipped() {
    // A 100 KB member name nests arrays of 32: every value's pointer is at
    // least that long, so ~20k values would copy about 2 GB of pointers.
    let name = "n".repeat(100 * 1024);
    let mut leaf = json!({"type": "string"});
    for _ in 0..3 {
        leaf = json!({"type": "array", "minItems": 32, "items": leaf});
    }
    let mut props = serde_json::Map::new();
    props.insert(name.clone(), leaf);
    let mut schemas = serde_json::Map::new();
    schemas.insert("Root".into(), json!({"type": "object", "required": [name], "properties": props}));
    let doc = doc_with_schemas(schemas, "Root");
    let r = import(&doc, &ImportOptions { max_bytes: 1024 * 1024, ..opts() }).unwrap();
    assert!(has(&r, "sample_size_limit"));
    let values = count_leaves(&json_body(&req(&r, "a").spec));
    assert!(values < 100, "{values} values generated");
    // Stored pointers are clipped.
    assert!(r.report.warnings.iter().all(|w| w.pointer.chars().count() <= 513), "a long pointer was stored");

    // A `$ref` longer than the limit is not followed.
    let mut schemas = serde_json::Map::new();
    schemas.insert("Root".into(), json!({"$ref": format!("#/components/schemas/{}", "x".repeat(4_096))}));
    let r = import(&doc_with_schemas(schemas, "Root"), &opts()).unwrap();
    assert!(has(&r, "ref_too_long"));
}

#[test]
fn findings_of_one_code_are_capped() {
    // 3000 paths without a leading '/', each warned at its own pointer.
    let mut paths = serde_json::Map::new();
    for i in 0..3_000 {
        paths.insert(format!("p{i}"), json!({}));
    }
    let doc = json!({"openapi": "3.0.0", "info": {"title": "t", "version": "1"}, "paths": paths});
    let r = import(doc.to_string().as_bytes(), &opts()).unwrap();
    let kept = r.report.warnings.iter().filter(|w| w.code == "path_not_absolute").count();
    assert_eq!(kept, 1_000);
    assert!(has(&r, "report_truncated"));
}

/// `paths` Path Items that all `$ref` `#/components/pathItems/Shared`.
fn shared_path_item_doc(paths: usize, shared: serde_json::Value) -> Vec<u8> {
    let mut map = serde_json::Map::new();
    for i in 0..paths {
        map.insert(format!("/p{i}"), json!({"$ref": "#/components/pathItems/Shared"}));
    }
    let doc = json!({
        "openapi": "3.1.0", "info": {"title": "t", "version": "1"}, "paths": map,
        "components": {"pathItems": {"Shared": shared}}
    });
    doc.to_string().into_bytes()
}

#[test]
fn shared_path_items_are_borrowed_and_their_text_charged() {
    // 20k paths share one Path Item with a 200 KB description and an
    // operation with another: 4 GB of Path Item copies, then 200 KB more per
    // imported operation. The item is read in place, and each operation's
    // text is charged, so a 2 MiB input limit (8 MiB of text) stops the
    // import after a few dozen operations.
    let big = "d".repeat(200 * 1024);
    let shared = json!({"description": big, "get": {"description": big, "responses": {}}});
    let r = import(&shared_path_item_doc(20_000, shared), &ImportOptions { max_bytes: 2 * 1024 * 1024, ..opts() }).unwrap();
    assert!(has(&r, "text_size_limit"));
    assert!((1..100).contains(&r.requests.len()), "{} requests", r.requests.len());
    assert_eq!(r.report.counts.operations_found, 20_000);
}

#[test]
fn repeated_operation_keys_take_the_next_free_suffix() {
    // 5000 operations share one 4 KB operationId: probing `#2`, `#3`, … for
    // each one formatted and hashed about 50 GB of keys.
    let id = "k".repeat(4 * 1024);
    let r = import(&shared_path_item_doc(5_000, json!({"get": {"operationId": id, "responses": {}}})), &opts()).unwrap();
    assert_eq!(r.requests.len(), 5_000);
    assert!(req(&r, &format!("{id}#5000")).spec.source.is_some());
    assert!(has(&r, "duplicate_operation_key"));
}

#[test]
fn server_variables_are_rendered_once() {
    // 50k uses of one variable whose enum has 50k values: the enum was
    // scanned and joined, and a variable added, for every use.
    let url = "https://example.com/{v}".repeat(50_000);
    let values: Vec<String> = (0..50_000).map(|i| format!("v{i}")).collect();
    let doc = json!({
        "openapi": "3.0.0", "info": {"title": "t", "version": "1"}, "paths": {},
        "servers": [{"url": url, "variables": {"v": {"default": "v49999", "enum": values}}}]
    });
    let r = import(doc.to_string().as_bytes(), &opts()).unwrap();
    let env = &r.environments[0];
    assert_eq!(env.variables.iter().filter(|v| v.name == "v").count(), 1);
    assert!(!has(&r, "contradictory_schema"));
}
