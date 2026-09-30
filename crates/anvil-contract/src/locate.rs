//! JSON Pointer → line/column in the original JSON or YAML text.
//!
//! The parsed document (`serde_json::Value`) carries no positions, so the
//! text is scanned once more to record where each member and item starts.
//! JSON is scanned exactly. YAML is scanned line by line for block
//! mappings and sequences, which is how OpenAPI documents are written; flow
//! collections (`{…}`, `[…]`) and multi-line scalars are skipped as a whole,
//! so pointers inside them resolve to the nearest enclosing member. A
//! pointer that was not seen resolves to its nearest recorded ancestor.

use anvil_import::Syntax;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// 1-based line and column (in characters) of a location in the source text.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct Position {
    pub line: u32,
    pub column: u32,
}

/// Positions of the members and items of one document.
#[derive(Debug, Default)]
pub struct Locator {
    map: HashMap<String, Position>,
}

impl Locator {
    pub fn new(text: &str, syntax: Syntax) -> Self {
        let text = text.strip_prefix('\u{feff}').unwrap_or(text);
        let mut map = HashMap::new();
        match syntax {
            Syntax::Json => JsonScan::new(text, &mut map).document(),
            _ => yaml_scan(text, &mut map),
        }
        Locator { map }
    }

    /// The position of `pointer`, or of its nearest recorded ancestor.
    pub fn position(&self, pointer: &str) -> Option<Position> {
        let mut p = pointer;
        loop {
            if let Some(pos) = self.map.get(p) {
                return Some(*pos);
            }
            if p.is_empty() {
                return None;
            }
            p = &p[..p.rfind('/').unwrap_or(0)];
        }
    }
}

/// Append one reference token to a JSON pointer (RFC 6901 escaping).
pub fn ptr(base: &str, token: &str) -> String {
    let mut out = String::with_capacity(base.len() + token.len() + 1);
    out.push_str(base);
    out.push('/');
    for c in token.chars() {
        match c {
            '~' => out.push_str("~0"),
            '/' => out.push_str("~1"),
            c => out.push(c),
        }
    }
    out
}

struct JsonScan<'a, 'm> {
    chars: std::iter::Peekable<std::str::Chars<'a>>,
    line: u32,
    col: u32,
    map: &'m mut HashMap<String, Position>,
}

impl<'a, 'm> JsonScan<'a, 'm> {
    fn new(text: &'a str, map: &'m mut HashMap<String, Position>) -> Self {
        JsonScan { chars: text.chars().peekable(), line: 1, col: 1, map }
    }

    fn pos(&self) -> Position {
        Position { line: self.line, column: self.col }
    }

    fn bump(&mut self) -> Option<char> {
        let c = self.chars.next()?;
        if c == '\n' {
            self.line += 1;
            self.col = 1;
        } else {
            self.col += 1;
        }
        Some(c)
    }

    fn ws(&mut self) {
        while self.chars.peek().is_some_and(|c| c.is_whitespace()) {
            self.bump();
        }
    }

    fn document(&mut self) {
        self.ws();
        let at = self.pos();
        self.map.insert(String::new(), at);
        self.value("", 0);
    }

    /// Scan one value. The caller already recorded its pointer.
    fn value(&mut self, pointer: &str, depth: usize) {
        self.ws();
        match self.chars.peek().copied() {
            Some('{') if depth < 256 => {
                self.bump();
                loop {
                    self.ws();
                    match self.chars.peek().copied() {
                        Some('}') => {
                            self.bump();
                            return;
                        }
                        Some(',') => {
                            self.bump();
                        }
                        Some('"') => {
                            let at = self.pos();
                            let key = self.string();
                            let child = ptr(pointer, &key);
                            self.map.entry(child.clone()).or_insert(at);
                            self.ws();
                            if self.chars.peek() == Some(&':') {
                                self.bump();
                            }
                            self.value(&child, depth + 1);
                        }
                        Some(_) => {
                            // Not valid JSON here; skip a character so the scan ends.
                            self.bump();
                        }
                        None => return,
                    }
                }
            }
            Some('[') if depth < 256 => {
                self.bump();
                let mut index = 0usize;
                loop {
                    self.ws();
                    match self.chars.peek().copied() {
                        Some(']') => {
                            self.bump();
                            return;
                        }
                        Some(',') => {
                            self.bump();
                        }
                        Some(_) => {
                            let at = self.pos();
                            let child = ptr(pointer, &index.to_string());
                            self.map.entry(child.clone()).or_insert(at);
                            self.value(&child, depth + 1);
                            index += 1;
                            if self.pos() == at {
                                // Not valid JSON here (a stray `}`): skip it so the scan ends.
                                self.bump();
                            }
                        }
                        None => return,
                    }
                }
            }
            Some('"') => {
                self.string();
            }
            Some(_) => {
                while self.chars.peek().is_some_and(|c| !matches!(c, ',' | '}' | ']') && !c.is_whitespace()) {
                    self.bump();
                }
            }
            None => {}
        }
    }

    fn string(&mut self) -> String {
        let mut out = String::new();
        self.bump(); // opening quote
        while let Some(c) = self.bump() {
            match c {
                '"' => break,
                '\\' => match self.bump() {
                    Some('n') => out.push('\n'),
                    Some('t') => out.push('\t'),
                    Some('r') => out.push('\r'),
                    Some('b') => out.push('\u{8}'),
                    Some('f') => out.push('\u{c}'),
                    Some('u') => {
                        let hex: String = (0..4).filter_map(|_| self.bump()).collect();
                        let hi = u32::from_str_radix(&hex, 16).unwrap_or(0xfffd);
                        let code = if (0xd800..0xdc00).contains(&hi) && self.chars.peek() == Some(&'\\') {
                            self.bump();
                            self.bump();
                            let hex: String = (0..4).filter_map(|_| self.bump()).collect();
                            let lo = u32::from_str_radix(&hex, 16).unwrap_or(0);
                            0x10000 + ((hi - 0xd800) << 10) + lo.wrapping_sub(0xdc00)
                        } else {
                            hi
                        };
                        out.push(char::from_u32(code).unwrap_or('\u{fffd}'));
                    }
                    Some(c) => out.push(c),
                    None => break,
                },
                c => out.push(c),
            }
        }
        out
    }
}

#[derive(Debug)]
enum FrameKind {
    Map,
    Seq { index: usize },
}

#[derive(Debug)]
struct Frame {
    indent: usize,
    pointer: String,
    kind: FrameKind,
    /// Pointer of the last key (map) or item (sequence) whose value may
    /// continue on the following, deeper lines.
    pending: Option<String>,
}

fn yaml_scan(text: &str, map: &mut HashMap<String, Position>) {
    map.insert(String::new(), Position { line: 1, column: 1 });
    let mut stack: Vec<Frame> = vec![];
    // Lines whose indentation is deeper than this belong to a block scalar
    // or multi-line flow value and are skipped.
    let mut skip_deeper_than: Option<usize> = None;
    let mut open_flow: i32 = 0;
    let mut open_quote: Option<char> = None;
    for (n, raw) in text.lines().enumerate() {
        let line_no = (n + 1) as u32;
        let indent = raw.chars().take_while(|c| *c == ' ').count();
        let content = raw[indent..].trim_end();
        if open_flow > 0 || open_quote.is_some() {
            scan_flow(content, &mut open_flow, &mut open_quote);
            continue;
        }
        if content.is_empty() || content.starts_with('#') {
            continue;
        }
        if let Some(limit) = skip_deeper_than {
            if indent > limit {
                continue;
            }
            skip_deeper_than = None;
        }
        if (n == 0 && content.starts_with('%')) || content == "---" || content == "..." || content.starts_with("--- ") {
            continue;
        }
        let mut col = indent;
        let mut rest = content;
        // A line may open several nested sequence items (`- - x`) and an
        // inline mapping (`- name: x`).
        loop {
            while stack.last().is_some_and(|f| f.indent > col) {
                stack.pop();
            }
            if let Some(item) = rest.strip_prefix('-').filter(|r| r.is_empty() || r.starts_with(' ')) {
                let parent_pointer = match stack.last_mut() {
                    Some(f) if f.indent == col && matches!(f.kind, FrameKind::Seq { .. }) => None,
                    Some(f) => f.pending.clone(),
                    None => Some(String::new()),
                };
                if let Some(p) = parent_pointer {
                    stack.push(Frame { indent: col, pointer: p, kind: FrameKind::Seq { index: 0 }, pending: None });
                } else if let Some(Frame { kind: FrameKind::Seq { index }, .. }) = stack.last_mut() {
                    *index += 1;
                }
                let Some(frame) = stack.last_mut() else { break };
                let FrameKind::Seq { index } = frame.kind else { break };
                let item_pointer = ptr(&frame.pointer, &index.to_string());
                map.entry(item_pointer.clone()).or_insert(Position { line: line_no, column: (col + 1) as u32 });
                frame.pending = Some(item_pointer);
                let trimmed = item.trim_start();
                col += 1 + (item.len() - trimmed.len());
                rest = trimmed;
                if rest.is_empty() {
                    break;
                }
                continue;
            }
            match split_key(rest) {
                Some((key, value)) => {
                    let same_map = stack.last().is_some_and(|f| f.indent == col && matches!(f.kind, FrameKind::Map));
                    if !same_map {
                        if stack.last().is_some_and(|f| f.indent == col) {
                            // A key at the indentation of a sequence ends that
                            // (indentless) sequence.
                            stack.pop();
                            continue;
                        }
                        let parent = match stack.last() {
                            Some(f) => f.pending.clone().unwrap_or_else(|| f.pointer.clone()),
                            None => String::new(),
                        };
                        stack.push(Frame { indent: col, pointer: parent, kind: FrameKind::Map, pending: None });
                    }
                    let Some(frame) = stack.last_mut() else { break };
                    let key_pointer = ptr(&frame.pointer, &key);
                    map.entry(key_pointer.clone()).or_insert(Position { line: line_no, column: (col + 1) as u32 });
                    frame.pending = Some(key_pointer);
                    let value = strip_comment(value).trim();
                    if is_block_scalar(value) {
                        skip_deeper_than = Some(col);
                    } else {
                        scan_flow(value, &mut open_flow, &mut open_quote);
                    }
                }
                None => {
                    // A scalar item or a continuation of a plain scalar.
                    scan_flow(strip_comment(rest), &mut open_flow, &mut open_quote);
                    if is_block_scalar(strip_comment(rest).trim()) {
                        skip_deeper_than = Some(col.saturating_sub(1));
                    }
                }
            }
            break;
        }
    }
}

fn is_block_scalar(v: &str) -> bool {
    let v = v.split_whitespace().next().unwrap_or("");
    // Optional anchor/tag before the indicator is rare in OpenAPI; ignore it.
    (v.starts_with('|') || v.starts_with('>')) && v[1..].chars().all(|c| c.is_ascii_digit() || c == '+' || c == '-')
}

/// Track open flow collections and quoted scalars that continue on the
/// following lines.
fn scan_flow(s: &str, open_flow: &mut i32, open_quote: &mut Option<char>) {
    let mut chars = s.chars().peekable();
    let starts_quoted = open_quote.is_some();
    let mut first = true;
    while let Some(c) = chars.next() {
        match *open_quote {
            Some('\'') => {
                if c == '\'' {
                    if chars.peek() == Some(&'\'') {
                        chars.next();
                    } else {
                        *open_quote = None;
                    }
                }
            }
            Some(_) => match c {
                '\\' => {
                    chars.next();
                }
                '"' => *open_quote = None,
                _ => {}
            },
            None => match c {
                // Quotes only open a scalar at its start or inside a flow collection.
                '\'' | '"' if first || *open_flow > 0 || starts_quoted => *open_quote = Some(c),
                '{' | '[' => *open_flow += 1,
                '}' | ']' => *open_flow = (*open_flow - 1).max(0),
                '#' if *open_flow > 0 => break,
                _ => {}
            },
        }
        if !c.is_whitespace() {
            first = false;
        }
    }
}

fn strip_comment(s: &str) -> &str {
    let mut quote: Option<char> = None;
    let mut prev_space = true;
    for (i, c) in s.char_indices() {
        match quote {
            Some(q) if c == q => quote = None,
            Some(_) => {}
            None if (c == '\'' || c == '"') && prev_space => quote = Some(c),
            None if c == '#' && prev_space => return &s[..i],
            None => {}
        }
        prev_space = c.is_whitespace();
    }
    s
}

/// Split `key: value` (plain, single- or double-quoted key). `None` when the
/// line is not a mapping entry.
fn split_key(s: &str) -> Option<(String, &str)> {
    let s_trim = s.strip_prefix("? ").unwrap_or(s);
    let mut chars = s_trim.char_indices();
    match s_trim.chars().next()? {
        q @ ('"' | '\'') => {
            chars.next();
            let mut key = String::new();
            let mut end = None;
            let mut escaped = false;
            while let Some((i, c)) = chars.next() {
                if q == '"' && escaped {
                    key.push(c);
                    escaped = false;
                } else if q == '"' && c == '\\' {
                    escaped = true;
                } else if c == q {
                    if q == '\'' && s_trim[i + 1..].starts_with('\'') {
                        key.push('\'');
                        chars.next();
                        continue;
                    }
                    end = Some(i + 1);
                    break;
                } else {
                    key.push(c);
                }
            }
            let after = s_trim[end?..].trim_start();
            let value = after.strip_prefix(':')?;
            (value.is_empty() || value.starts_with(' ')).then_some((key, value))
        }
        '{' | '[' | '#' | '&' | '*' | '!' | '|' | '>' | '%' | '@' | '`' => None,
        _ => {
            let bytes = s_trim.as_bytes();
            for (i, &b) in bytes.iter().enumerate() {
                if b == b':' && (i + 1 == bytes.len() || bytes[i + 1] == b' ' || bytes[i + 1] == b'\t') {
                    let key = s_trim[..i].trim_end();
                    if key.is_empty() {
                        return None;
                    }
                    return Some((key.to_string(), &s_trim[i + 1..]));
                }
                if b == b' ' && bytes.get(i + 1) == Some(&b'#') {
                    return None;
                }
            }
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn at(l: &Locator, p: &str) -> (u32, u32) {
        let pos = l.position(p).unwrap();
        (pos.line, pos.column)
    }

    #[test]
    fn json_positions() {
        let text = "{\n  \"paths\": {\n    \"/pets/{id}\": {\n      \"get\": {\"responses\": {\"200\": {}}}\n    }\n  },\n  \"tags\": [\"a\", {\"name\": \"b\"}]\n}";
        let l = Locator::new(text, Syntax::Json);
        assert_eq!(at(&l, "/paths"), (2, 3));
        assert_eq!(at(&l, "/paths/~1pets~1{id}/get"), (4, 7));
        assert_eq!(at(&l, "/paths/~1pets~1{id}/get/responses/200"), (4, 29));
        assert_eq!(at(&l, "/tags/1/name"), (7, 18));
        // Unknown pointers resolve to their nearest ancestor.
        assert_eq!(at(&l, "/paths/~1pets~1{id}/get/responses/200/description"), (4, 29));
    }

    #[test]
    fn malformed_json_ends() {
        for text in ["[}", "[}}]", "{\"a\": [1, }, 2]}", "[:", "{\"a\" 1 [}"] {
            let l = Locator::new(text, Syntax::Json);
            assert!(l.map.len() < 10, "{text}: {:?}", l.map);
        }
    }

    #[test]
    fn json_escapes_in_keys() {
        let text = r#"{"a\"b": {"c\u00e9": 1}}"#;
        let l = Locator::new(text, Syntax::Json);
        assert_eq!(at(&l, "/a\"b/cé"), (1, 11));
    }

    #[test]
    fn yaml_block_structure() {
        let text = "openapi: 3.1.0\ninfo:\n  title: x\n  description: |\n    first: not a key\n    - not an item\n  version: '1'\npaths:\n  /pets:\n    get:\n      parameters:\n        - name: limit\n          in: query\n        - $ref: '#/components/parameters/X'\n      tags:\n      - a\n      - b\n      responses:\n        '200':\n          description: ok\n";
        let l = Locator::new(text, Syntax::Yaml);
        assert_eq!(at(&l, "/info/description"), (4, 3));
        assert_eq!(at(&l, "/info/version"), (7, 3));
        assert!(!l.map.contains_key("/info/first"));
        assert_eq!(at(&l, "/paths/~1pets/get/parameters/0"), (12, 9));
        assert_eq!(at(&l, "/paths/~1pets/get/parameters/0/in"), (13, 11));
        assert_eq!(at(&l, "/paths/~1pets/get/parameters/1/$ref"), (14, 11));
        assert_eq!(at(&l, "/paths/~1pets/get/tags/1"), (17, 7));
        assert_eq!(at(&l, "/paths/~1pets/get/responses/200/description"), (20, 11));
    }

    #[test]
    fn yaml_flow_and_multiline_values_are_skipped() {
        let text = "a:\n  b: { x: 1,\n    y: 2 }\n  c: \"multi\n    line: no\"\n  d: [1,\n    2]\n  e: 1\n";
        let l = Locator::new(text, Syntax::Yaml);
        assert_eq!(at(&l, "/a/b/y"), (2, 3));
        assert!(!l.map.contains_key("/a/line"));
        assert_eq!(at(&l, "/a/e"), (8, 3));
    }

    #[test]
    fn yaml_nested_sequences_and_comments() {
        let text = "# c\nlist:\n  - - x # comment\n    - y\n  - k: v # c\n    j: w\nnext: 1\n";
        let l = Locator::new(text, Syntax::Yaml);
        assert_eq!(at(&l, "/list/0/0"), (3, 5));
        assert_eq!(at(&l, "/list/0/1"), (4, 5));
        assert_eq!(at(&l, "/list/1/k"), (5, 5));
        assert_eq!(at(&l, "/list/1/j"), (6, 5));
        assert_eq!(at(&l, "/next"), (7, 1));
    }
}
