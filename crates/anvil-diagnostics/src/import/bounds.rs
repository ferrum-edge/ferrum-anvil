use super::{ImportError, MAX_ARRAY_ITEMS, MAX_BYTES, MAX_DEPTH, MAX_NODES, MAX_OBJECT_MEMBERS, MAX_STRING_BYTES};
use serde::de::{DeserializeSeed, Error, MapAccess, SeqAccess, Visitor};
use serde_json::{Map, Number, Value};
use std::fmt;

pub(super) fn parse(input: &[u8]) -> Result<Value, ImportError> {
    preflight(input)?;
    let mut deserializer = serde_json::Deserializer::from_slice(input);
    let mut nodes = 0;
    let value = Seed(&mut nodes)
        .deserialize(&mut deserializer)
        .map_err(|error| if error.to_string().contains("import limit") { ImportError::Limit } else { ImportError::Json })?;
    deserializer.end().map_err(|_| ImportError::Json)?;
    Ok(value)
}

/// Lexical limits run before serde allocates any untrusted JSON tree. Braces,
/// quotes and escapes inside strings do not contribute to nesting or token counts.
fn preflight(input: &[u8]) -> Result<(), ImportError> {
    if input.len() > MAX_BYTES {
        return Err(ImportError::Limit);
    }
    std::str::from_utf8(input).map_err(|_| ImportError::Json)?;
    let mut depth = 0usize;
    let mut tokens = 0usize;
    let mut quoted = false;
    let mut escaped = false;
    let mut string_bytes = 0usize;
    let mut scalar = false;
    for &byte in input {
        if quoted {
            string_bytes += 1;
            // A decoded character can require six JSON bytes (\uXXXX).
            if string_bytes > MAX_STRING_BYTES * 6 + 1 {
                return Err(ImportError::Limit);
            }
            if escaped {
                escaped = false;
            } else if byte == b'\\' {
                escaped = true;
            } else if byte == b'"' {
                quoted = false;
            }
            continue;
        }
        match byte {
            b'"' => {
                quoted = true;
                string_bytes = 0;
                tokens += 1;
                scalar = false;
            }
            b'{' | b'[' => {
                depth += 1;
                tokens += 1;
                scalar = false;
                if depth > MAX_DEPTH {
                    return Err(ImportError::Limit);
                }
            }
            b'}' | b']' => {
                depth = depth.checked_sub(1).ok_or(ImportError::Json)?;
                scalar = false;
            }
            b',' | b':' | b' ' | b'\t' | b'\r' | b'\n' => scalar = false,
            _ => {
                if !scalar {
                    tokens += 1;
                    scalar = true;
                }
            }
        }
        if tokens > MAX_NODES * 2 {
            return Err(ImportError::Limit);
        }
    }
    if quoted || depth != 0 {
        return Err(ImportError::Json);
    }
    Ok(())
}

struct Seed<'a>(&'a mut usize);

impl<'de> DeserializeSeed<'de> for Seed<'_> {
    type Value = Value;

    fn deserialize<D: serde::Deserializer<'de>>(self, de: D) -> Result<Value, D::Error> {
        *self.0 += 1;
        if *self.0 > MAX_NODES {
            return Err(D::Error::custom("import limit"));
        }
        de.deserialize_any(BoundedVisitor(self.0))
    }
}

struct BoundedVisitor<'a>(&'a mut usize);

impl<'de> Visitor<'de> for BoundedVisitor<'_> {
    type Value = Value;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("bounded JSON")
    }

    fn visit_bool<E: Error>(self, value: bool) -> Result<Value, E> {
        Ok(Value::Bool(value))
    }

    fn visit_i64<E: Error>(self, value: i64) -> Result<Value, E> {
        Ok(Value::Number(value.into()))
    }

    fn visit_u64<E: Error>(self, value: u64) -> Result<Value, E> {
        Ok(Value::Number(value.into()))
    }

    fn visit_f64<E: Error>(self, value: f64) -> Result<Value, E> {
        Number::from_f64(value).map(Value::Number).ok_or_else(|| E::custom("nonfinite number"))
    }

    fn visit_str<E: Error>(self, value: &str) -> Result<Value, E> {
        if value.len() > MAX_STRING_BYTES {
            return Err(E::custom("import limit"));
        }
        Ok(Value::String(value.into()))
    }

    fn visit_unit<E: Error>(self) -> Result<Value, E> {
        Ok(Value::Null)
    }

    fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<Value, A::Error> {
        let mut values = Vec::new();
        while let Some(value) = seq.next_element_seed(Seed(self.0))? {
            if values.len() == MAX_ARRAY_ITEMS {
                return Err(A::Error::custom("import limit"));
            }
            values.push(value);
        }
        Ok(Value::Array(values))
    }

    fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Value, A::Error> {
        let mut values = Map::new();
        while let Some(key) = map.next_key::<String>()? {
            if key.len() > MAX_STRING_BYTES || values.len() == MAX_OBJECT_MEMBERS {
                return Err(A::Error::custom("import limit"));
            }
            if values.contains_key(&key) {
                return Err(A::Error::custom("duplicate key"));
            }
            let value = map.next_value_seed(Seed(self.0))?;
            values.insert(key, value);
        }
        Ok(Value::Object(values))
    }
}
