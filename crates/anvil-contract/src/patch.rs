//! Suggested changes to a description: applying them, rendering them as a
//! fragment of the document, and as an RFC 6902 JSON Patch.

use anvil_import::Syntax;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value, json};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum PatchKind {
    /// Set the value (JSON `null` when absent), creating missing parents. On
    /// an existing object the new members are merged in and existing ones
    /// are kept.
    Add,
    /// Set the value, creating missing parents.
    Replace,
    Remove,
    /// Add the items of the value (a list) that the list at the path lacks;
    /// set the value when there is nothing there yet. A single value there
    /// (`type: integer`, `produces: x`) becomes a one-item list first.
    Union,
}

/// One change at an RFC 6901 pointer.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct PatchOp {
    pub op: PatchKind,
    pub path: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub value: Option<Value>,
}

impl PatchOp {
    pub fn add(path: impl Into<String>, value: Value) -> Self {
        PatchOp { op: PatchKind::Add, path: path.into(), value: Some(value) }
    }

    pub fn replace(path: impl Into<String>, value: Value) -> Self {
        PatchOp { op: PatchKind::Replace, path: path.into(), value: Some(value) }
    }

    pub fn remove(path: impl Into<String>) -> Self {
        PatchOp { op: PatchKind::Remove, path: path.into(), value: None }
    }

    pub fn union(path: impl Into<String>, items: Vec<Value>) -> Self {
        PatchOp { op: PatchKind::Union, path: path.into(), value: Some(Value::Array(items)) }
    }
}

fn tokens(pointer: &str) -> Vec<String> {
    pointer.split('/').skip(1).map(|t| t.replace("~1", "/").replace("~0", "~")).collect()
}

/// Deep-merge `add` into `into`, keeping what `into` already has (scalars
/// and lists already there win).
fn merge_keep(into: &mut Value, add: Value) {
    if let (Value::Object(a), Value::Object(b)) = (into, add) {
        for (k, v) in b {
            match a.get_mut(&k) {
                Some(existing) => merge_keep(existing, v),
                None => {
                    a.insert(k, v);
                }
            }
        }
    }
}

/// Apply `ops` in order. Returns how many could not be applied (a parent
/// that is a scalar, an index out of range).
pub fn apply(doc: &mut Value, ops: &[PatchOp]) -> usize {
    let mut failed = 0;
    for op in ops {
        let toks = tokens(&op.path);
        let Some((last, parents)) = toks.split_last() else {
            // The whole document.
            match op.op {
                PatchKind::Add => merge_keep(doc, op.value.clone().unwrap_or(Value::Null)),
                PatchKind::Replace | PatchKind::Union => *doc = op.value.clone().unwrap_or(Value::Null),
                PatchKind::Remove => failed += 1,
            }
            continue;
        };
        // Removing creates nothing: the target must exist.
        let cur = if op.op == PatchKind::Remove { walk_existing(doc, parents) } else { walk_to(doc, parents, &toks) };
        let Some(cur) = cur else {
            failed += 1;
            continue;
        };
        match (op.op, cur) {
            (PatchKind::Remove, Value::Object(o)) => {
                if o.shift_remove(last).is_none() {
                    failed += 1;
                }
            }
            (PatchKind::Remove, Value::Array(a)) => match last.parse::<usize>() {
                Ok(i) if i < a.len() => {
                    a.remove(i);
                }
                _ => failed += 1,
            },
            (PatchKind::Add, Value::Object(o)) => {
                let v = op.value.clone().unwrap_or(Value::Null);
                match o.get_mut(last) {
                    Some(existing) => merge_keep(existing, v),
                    None => {
                        o.insert(last.clone(), v);
                    }
                }
            }
            (PatchKind::Union, Value::Object(o)) => {
                let items = match op.value.clone() {
                    Some(Value::Array(a)) => a,
                    Some(v) => vec![v],
                    None => vec![],
                };
                match o.get_mut(last) {
                    Some(Value::Array(existing)) => {
                        for i in items {
                            if !existing.contains(&i) {
                                existing.push(i);
                            }
                        }
                    }
                    Some(Value::Object(_)) => failed += 1,
                    Some(single) => {
                        let mut list = if single.is_null() { vec![] } else { vec![single.take()] };
                        for i in items {
                            if !list.contains(&i) {
                                list.push(i);
                            }
                        }
                        *single = Value::Array(list);
                    }
                    None => {
                        o.insert(last.clone(), Value::Array(items));
                    }
                }
            }
            (PatchKind::Replace, Value::Object(o)) => {
                o.insert(last.clone(), op.value.clone().unwrap_or(Value::Null));
            }
            (PatchKind::Add | PatchKind::Replace, Value::Array(a)) => {
                let v = op.value.clone().unwrap_or(Value::Null);
                match last.as_str() {
                    "-" => a.push(v),
                    i => match i.parse::<usize>() {
                        Ok(i) if i < a.len() && op.op == PatchKind::Replace => a[i] = v,
                        Ok(i) if i <= a.len() => a.insert(i, v),
                        _ => failed += 1,
                    },
                }
            }
            _ => failed += 1,
        }
    }
    failed
}

/// Apply all of `ops` or none of them: before each op, what it may change
/// is recorded (the value at its target, or the member or list length it
/// creates), and after a failed op the changes are undone in reverse. Only
/// the targets are copied, never the document.
pub fn apply_atomic(doc: &mut Value, ops: &[PatchOp]) -> bool {
    let mut undo = Vec::with_capacity(ops.len());
    for op in ops {
        undo.push(undo_for(doc, op));
        if apply(doc, std::slice::from_ref(op)) > 0 {
            for u in undo.into_iter().rev() {
                restore(doc, u);
            }
            return false;
        }
    }
    true
}

/// How to undo one op.
enum Undo {
    Nothing,
    /// Put this value back at the pointer.
    Set(Vec<String>, Value),
    /// Remove a member the op created (with any parents under it).
    RemoveKey(Vec<String>, String),
    /// Shorten a list the op appended to.
    Truncate(Vec<String>, usize),
    /// Put back a member the op removed, at its position.
    Reinsert(Vec<String>, String, usize, Value),
}

fn undo_for(doc: &Value, op: &PatchOp) -> Undo {
    let toks = tokens(&op.path);
    if toks.is_empty() {
        return Undo::Set(vec![], doc.clone());
    }
    let mut node = doc;
    for (i, t) in toks.iter().enumerate() {
        let last = i + 1 == toks.len();
        match node {
            Value::Object(o) => match o.get(t) {
                Some(child) if last && op.op == PatchKind::Remove => {
                    let at = o.keys().position(|k| k == t).unwrap_or(0);
                    return Undo::Reinsert(toks[..i].to_vec(), t.clone(), at, child.clone());
                }
                Some(child) if last => return Undo::Set(toks.clone(), child.clone()),
                Some(child) => node = child,
                // A remove creates nothing; any other op creates this member.
                None if op.op == PatchKind::Remove => return Undo::Nothing,
                None => return Undo::RemoveKey(toks[..i].to_vec(), t.clone()),
            },
            Value::Array(a) => {
                if t == "-" {
                    return Undo::Truncate(toks[..i].to_vec(), a.len());
                }
                if last {
                    // An insert or removal shifts the items: keep the list.
                    return Undo::Set(toks[..i].to_vec(), node.clone());
                }
                match t.parse::<usize>().ok().and_then(|k| a.get(k)) {
                    Some(child) => node = child,
                    None => return Undo::Nothing,
                }
            }
            // The op fails here without changing anything.
            _ => return Undo::Nothing,
        }
    }
    Undo::Nothing
}

fn restore(doc: &mut Value, u: Undo) {
    match u {
        Undo::Nothing => {}
        Undo::Set(at, v) => {
            if let Some(n) = walk_existing(doc, &at) {
                *n = v;
            }
        }
        Undo::RemoveKey(at, k) => {
            if let Some(Value::Object(o)) = walk_existing(doc, &at) {
                o.shift_remove(&k);
            }
        }
        Undo::Truncate(at, len) => {
            if let Some(Value::Array(a)) = walk_existing(doc, &at) {
                a.truncate(len);
            }
        }
        Undo::Reinsert(at, k, i, v) => {
            if let Some(Value::Object(o)) = walk_existing(doc, &at) {
                let i = i.min(o.len());
                o.shift_insert(i, k, v);
            }
        }
    }
}

/// The parent of the last token, creating missing objects (a list when the
/// next token appends to one, `-`).
fn walk_to<'v>(mut cur: &'v mut Value, parents: &[String], toks: &[String]) -> Option<&'v mut Value> {
    for (i, t) in parents.iter().enumerate() {
        let child_is_list = toks.get(i + 1).is_some_and(|n| n == "-");
        cur = match cur {
            Value::Object(o) => {
                o.entry(t.clone()).or_insert_with(|| if child_is_list { Value::Array(vec![]) } else { Value::Object(Map::new()) })
            }
            Value::Array(a) => a.get_mut(t.parse::<usize>().ok()?)?,
            _ => return None,
        };
    }
    Some(cur)
}

fn walk_existing<'v>(mut cur: &'v mut Value, parents: &[String]) -> Option<&'v mut Value> {
    for t in parents {
        cur = match cur {
            Value::Object(o) => o.get_mut(t)?,
            Value::Array(a) => a.get_mut(t.parse::<usize>().ok()?)?,
            _ => return None,
        };
    }
    Some(cur)
}

fn escape(t: &str) -> String {
    t.replace('~', "~0").replace('/', "~1")
}

/// RFC 6902 operations that turn `from` into `to`.
pub fn diff(from: &Value, to: &Value) -> Vec<Value> {
    let mut out = vec![];
    diff_at(from, to, "", &mut out);
    out
}

fn diff_at(a: &Value, b: &Value, at: &str, out: &mut Vec<Value>) {
    if a == b {
        return;
    }
    match (a, b) {
        (Value::Object(x), Value::Object(y)) => {
            for k in x.keys().filter(|k| !y.contains_key(*k)) {
                out.push(json!({"op": "remove", "path": format!("{at}/{}", escape(k))}));
            }
            for (k, v) in y {
                let p = format!("{at}/{}", escape(k));
                match x.get(k) {
                    Some(old) => diff_at(old, v, &p, out),
                    None => out.push(json!({"op": "add", "path": p, "value": v})),
                }
            }
        }
        // Items appended to a list are added one by one.
        (Value::Array(x), Value::Array(y)) if y.len() > x.len() && y.starts_with(x) => {
            for v in &y[x.len()..] {
                out.push(json!({"op": "add", "path": format!("{at}/-"), "value": v}));
            }
        }
        _ => out.push(json!({"op": "replace", "path": at, "value": b})),
    }
}

/// The part of the document `ops` touch, nested from the root, rendered in
/// `syntax` (a fragment to paste into the document by hand).
pub fn fragment(ops: &[PatchOp], syntax: Syntax) -> String {
    let mut root = Value::Object(Map::new());
    let mut removed = vec![];
    for op in ops {
        match op.op {
            PatchKind::Remove => removed.push(op.path.clone()),
            _ => {
                let mut nested = op.value.clone().unwrap_or(Value::Null);
                for t in tokens(&op.path).into_iter().rev() {
                    let mut m = Map::new();
                    m.insert(t, nested);
                    nested = Value::Object(m);
                }
                merge_keep(&mut root, nested);
            }
        }
    }
    let mut text = render(&root, syntax);
    for r in removed {
        text.push_str(&format!("# remove {r}\n"));
    }
    text
}

/// A whole document (or fragment) as JSON (2-space indent) or YAML.
pub fn render(v: &Value, syntax: Syntax) -> String {
    match syntax {
        Syntax::Json => {
            let mut s = serde_json::to_string_pretty(v).unwrap_or_default();
            s.push('\n');
            s
        }
        _ => serde_norway::to_string(v).unwrap_or_default(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn atomic_application_undoes_every_kind_of_change() {
        let original = json!({"a": {"x": 1, "y": [1, 2], "z": "s"}, "b": [0, 1, 2], "t": "integer"});
        let fail = PatchOp::remove("/no/such");
        let changes = vec![
            PatchOp::add("/a/new/deep/er", json!(1)),
            PatchOp::add("/a/y/-", json!(3)),
            PatchOp::remove("/a/x"),
            PatchOp::replace("/a/z", json!({"k": 1})),
            PatchOp::add("/b/1", json!(9)),
            PatchOp::remove("/b/0"),
            PatchOp::union("/t", vec![json!("null")]),
            PatchOp::add("/a", json!({"merged": true})),
        ];
        for n in 1..=changes.len() {
            let mut doc = original.clone();
            let mut ops = changes[..n].to_vec();
            ops.push(fail.clone());
            assert!(!apply_atomic(&mut doc, &ops));
            assert_eq!(doc, original, "after {n} changes");
            // Member order is kept too.
            assert_eq!(doc["a"].as_object().unwrap().keys().collect::<Vec<_>>(), ["x", "y", "z"]);
        }
        let mut doc = original.clone();
        assert!(apply_atomic(&mut doc, &changes));
        assert_eq!(doc["t"], json!(["integer", "null"]), "a single value becomes a list");
        assert!(doc["a"].get("x").is_none() && doc["a"]["merged"] == json!(true));
    }

    #[test]
    fn add_creates_parents_and_merges() {
        let mut doc = json!({"paths": {"/a": {"get": {"responses": {"200": {"description": "ok"}}}}}});
        let failed = apply(
            &mut doc,
            &[
                PatchOp::add("/paths/~1a/get/responses/404", json!({"description": "missing"})),
                PatchOp::add("/paths/~1b/post/responses/201", json!({"description": "made"})),
                PatchOp::add("/paths/~1b/post", json!({"summary": "x", "responses": {"201": {"description": "not overwritten"}}})),
                PatchOp::replace("/paths/~1a/get/responses/200/description", json!("fine")),
                PatchOp::add("/tags/-", json!({"name": "t"})),
                PatchOp { op: PatchKind::Remove, path: "/paths/~1a/get/responses/404/description".into(), value: None },
                PatchOp::add("/paths/~1a/get/responses/200/description/x", json!(1)),
            ],
        );
        assert_eq!(failed, 1, "a scalar parent refuses a member");
        assert_eq!(doc["tags"], json!([{"name": "t"}]));
        assert_eq!(
            apply(
                &mut doc,
                &[PatchOp::union("/produces", vec![json!("a"), json!("b")]), PatchOp::union("/produces", vec![json!("a"), json!("c")])]
            ),
            0
        );
        assert_eq!(doc["produces"], json!(["a", "b", "c"]));
        assert_eq!(doc["paths"]["/a"]["get"]["responses"]["404"], json!({}));
        assert_eq!(doc["paths"]["/b"]["post"], json!({"responses": {"201": {"description": "made"}}, "summary": "x"}));
        assert_eq!(doc["paths"]["/a"]["get"]["responses"]["200"]["description"], "fine");
    }

    #[test]
    fn diff_round_trips() {
        let a = json!({"a": 1, "b": {"c": [1, 2], "d": "x"}, "e~/f": true});
        let b = json!({"a": 1, "b": {"c": [1, 3], "g": null}, "h": {"i": 1}, "l": [1, 2, 3]});
        let a = {
            let mut a = a;
            a["l"] = json!([1]);
            a
        };
        let ops = diff(&a, &b);
        assert!(ops.contains(&json!({"op": "remove", "path": "/e~0~1f"})));
        assert!(ops.contains(&json!({"op": "replace", "path": "/b/c", "value": [1, 3]})));
        assert!(ops.contains(&json!({"op": "add", "path": "/h", "value": {"i": 1}})));
        assert!(ops.contains(&json!({"op": "add", "path": "/l/-", "value": 2})));
        // Applying the diff gives `b` back.
        let mut x = a.clone();
        let as_ops: Vec<PatchOp> = ops.iter().map(|o| serde_json::from_value(o.clone()).unwrap()).collect();
        assert_eq!(apply(&mut x, &as_ops), 0);
        assert_eq!(x, b);
    }

    #[test]
    fn fragments_nest_from_the_root() {
        let ops = [
            PatchOp::add("/paths/~1pets~1{id}/get/responses/404", json!({"description": "Not Found"})),
            PatchOp::add("/paths/~1pets~1{id}/get/responses/410", json!({"description": "Gone"})),
        ];
        let y = fragment(&ops, Syntax::Yaml);
        assert!(y.contains("/pets/{id}:") && y.contains("'404':") && y.contains("'410':"), "{y}");
        let j = fragment(&ops, Syntax::Json);
        let v: Value = serde_json::from_str(&j).unwrap();
        assert_eq!(v["paths"]["/pets/{id}"]["get"]["responses"]["410"]["description"], "Gone");
    }
}
