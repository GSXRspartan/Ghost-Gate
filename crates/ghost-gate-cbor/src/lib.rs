//   Copyright 2026 Ghost Gate contributors
//   SPDX-License-Identifier: MIT

//! Strict, bounded decoding of the base64 CBOR blobs the post-reset Ootle indexer serves.
//!
//! Upstream PRs #3100/#3101/#3107/#3110 change the indexer REST API: engine values
//! (`state.up.substate`, execution results, receipts, events, resources, dry-run results, UTXOs)
//! are now served as the committee-committed CBOR bytes, base64 in the JSON envelope, instead of a
//! lossy JSON projection. A verifier must hash and read exactly those committed bytes.
//!
//! This crate does ONE thing: turn such an envelope into a strict, bounded, generic [`CborValue`]
//! while preserving the exact committed bytes. It is deliberately isolated — it depends on no Tari
//! Ootle cohort — so the final reset-compatible release can be adopted by mapping [`CborValue`] (or
//! the preserved bytes) onto the real engine types, without rewriting the rest of Ghost Gate.
//!
//! What this crate is NOT:
//! - It is **not verification**. A decoded value is untrusted transport data. Decoding never
//!   establishes that a value is on chain, let alone independently consensus-verified; the trust
//!   classification (operator-trusted indexer assertion vs. independently verified consensus) lives
//!   in the policy layer and is unaffected by anything here. This crate produces no trust marker.
//! - It is **not** a replacement for the v0.47 JSON path. It is additive and consumed by nobody yet,
//!   so it cannot change existing behaviour.

use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use minicbor::data::Token;
use thiserror::Error;

/// Conservative defaults. A substate value is small; these bound memory and recursion well above
/// any legitimate engine value while refusing a hostile blob long before it can do damage.
pub const DEFAULT_MAX_BYTES: usize = 64 * 1024;
pub const DEFAULT_MAX_DEPTH: u32 = 16;
pub const DEFAULT_MAX_ITEMS: u64 = 4096;

/// Decode limits. All three are hard caps: exceeding any one is a refusal, never a truncation.
#[derive(Debug, Clone, Copy)]
pub struct Limits {
    /// Maximum decoded byte length, checked BEFORE any parsing.
    pub max_bytes: usize,
    /// Maximum nesting depth of arrays, maps and tags.
    pub max_depth: u32,
    /// Maximum number of elements in any one array or map (keys+values counted as a pair).
    pub max_items: u64,
}

impl Default for Limits {
    fn default() -> Self {
        Self { max_bytes: DEFAULT_MAX_BYTES, max_depth: DEFAULT_MAX_DEPTH, max_items: DEFAULT_MAX_ITEMS }
    }
}

/// A decoded CBOR value. Generic on purpose: it represents the committed value's SHAPE without
/// committing this crate to any cohort's engine types.
#[derive(Debug, Clone, PartialEq)]
pub enum CborValue {
    Int(i128),
    Bytes(Vec<u8>),
    Text(String),
    Array(Vec<CborValue>),
    Map(Vec<(CborValue, CborValue)>),
    Bool(bool),
    Null,
    Float(f64),
    Tag(u64, Box<CborValue>),
}

#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum CborError {
    #[error("input is {len} bytes, over the {max}-byte maximum")]
    TooLarge { len: usize, max: usize },
    #[error("input is not valid canonical base64")]
    Base64,
    #[error("CBOR is malformed or truncated: {0}")]
    Malformed(String),
    #[error("CBOR nesting exceeds the maximum depth of {max}")]
    TooDeep { max: u32 },
    #[error("a CBOR collection exceeds the maximum of {max} items")]
    TooWide { max: u64 },
    #[error("unsupported CBOR construct: {0}")]
    Unsupported(&'static str),
    #[error("{len} trailing byte(s) after the CBOR value")]
    TrailingData { len: usize },
    #[error("expected a CBOR {expected}, found {found}")]
    UnexpectedType { expected: &'static str, found: &'static str },
}

/// The committed bytes plus a structured view of them. The bytes are preserved EXACTLY as served,
/// including a non-canonical encoding (a non-minimal integer, an f32, an indefinite-length string),
/// so a later verifier hashes the committee-committed form rather than a re-serialisation of it.
#[derive(Debug, Clone, PartialEq)]
pub struct CommittedValue {
    bytes: Vec<u8>,
    value: CborValue,
}

impl CommittedValue {
    /// The exact committed bytes, for hashing against the state-tree leaf. This is the form a
    /// consensus verifier must bind to — never a re-encoding of [`value`](Self::value).
    pub fn committed_bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// The structured view, for reading fields. Reading a field is NOT verifying it.
    pub fn value(&self) -> &CborValue {
        &self.value
    }

    pub fn into_parts(self) -> (Vec<u8>, CborValue) {
        (self.bytes, self.value)
    }
}

/// Decode a base64 CBOR envelope (the indexer's wire form) into a [`CommittedValue`].
///
/// Base64 is STANDARD with canonical padding, matching the indexer's `ootle_serde::base64`
/// serializer; anything else — whitespace, URL-safe alphabet, non-canonical padding — is refused.
pub fn decode_committed_base64(b64: &str, limits: Limits) -> Result<CommittedValue, CborError> {
    // Bound the ENCODED length too, so a hostile multi-megabyte string cannot force a large
    // allocation during base64 decoding before the byte cap is applied. 4/3 plus padding slack.
    if b64.len() > limits.max_bytes.saturating_mul(4) / 3 + 4 {
        return Err(CborError::TooLarge { len: b64.len(), max: limits.max_bytes });
    }
    let bytes = STANDARD.decode(b64.as_bytes()).map_err(|_| CborError::Base64)?;
    decode_committed_bytes(&bytes, limits)
}

/// Decode raw CBOR bytes (the already-base64-decoded form) into a [`CommittedValue`].
pub fn decode_committed_bytes(bytes: &[u8], limits: Limits) -> Result<CommittedValue, CborError> {
    if bytes.len() > limits.max_bytes {
        return Err(CborError::TooLarge { len: bytes.len(), max: limits.max_bytes });
    }
    // Tokenise the WHOLE input. A truncated value makes the tokenizer error (`Malformed`); a value
    // followed by more data yields extra tokens, which the one-value parse below reports as
    // trailing data. The token stream borrows `bytes`, so no engine type or cohort is involved.
    let mut tokens: Vec<Token> = Vec::new();
    {
        let mut decoder = minicbor::Decoder::new(bytes);
        for token in decoder.tokens() {
            tokens.push(token.map_err(|e| CborError::Malformed(e.to_string()))?);
        }
    }
    let mut cursor = 0usize;
    let value = parse(&tokens, &mut cursor, 0, &limits)?;
    if cursor != tokens.len() {
        // A complete first value, then more: reject rather than ignore the remainder.
        return Err(CborError::TrailingData { len: tokens.len() - cursor });
    }
    Ok(CommittedValue { bytes: bytes.to_vec(), value })
}

fn int_to_i128(i: minicbor::data::Int) -> Result<i128, CborError> {
    // CBOR integers span -(2^64)..=2^64-1, all within i128. minicbor exposes u64/i64 conversions;
    // the thin sliver below i64::MIN is not produced by engine values and is refused rather than
    // silently lost.
    if let Ok(u) = u64::try_from(i) {
        Ok(u as i128)
    } else if let Ok(v) = i64::try_from(i) {
        Ok(v as i128)
    } else {
        Err(CborError::Unsupported("integer outside the supported 64-bit range"))
    }
}

fn next<'a>(tokens: &'a [Token], cursor: &mut usize) -> Result<&'a Token<'a>, CborError> {
    let t = tokens.get(*cursor).ok_or_else(|| CborError::Malformed("unexpected end of CBOR".into()))?;
    *cursor += 1;
    Ok(t)
}

fn parse(tokens: &[Token], cursor: &mut usize, depth: u32, limits: &Limits) -> Result<CborValue, CborError> {
    if depth > limits.max_depth {
        return Err(CborError::TooDeep { max: limits.max_depth });
    }
    match next(tokens, cursor)? {
        Token::Bool(b) => Ok(CborValue::Bool(*b)),
        Token::Null => Ok(CborValue::Null),
        Token::U8(n) => Ok(CborValue::Int(*n as i128)),
        Token::U16(n) => Ok(CborValue::Int(*n as i128)),
        Token::U32(n) => Ok(CborValue::Int(*n as i128)),
        Token::U64(n) => Ok(CborValue::Int(*n as i128)),
        Token::I8(n) => Ok(CborValue::Int(*n as i128)),
        Token::I16(n) => Ok(CborValue::Int(*n as i128)),
        Token::I32(n) => Ok(CborValue::Int(*n as i128)),
        Token::I64(n) => Ok(CborValue::Int(*n as i128)),
        Token::Int(i) => Ok(CborValue::Int(int_to_i128(*i)?)),
        Token::F16(f) | Token::F32(f) => Ok(CborValue::Float(*f as f64)),
        Token::F64(f) => Ok(CborValue::Float(*f)),
        Token::Bytes(b) => Ok(CborValue::Bytes(b.to_vec())),
        Token::String(s) => Ok(CborValue::Text((*s).to_string())),
        Token::Array(n) => {
            let n = *n;
            if n > limits.max_items {
                return Err(CborError::TooWide { max: limits.max_items });
            }
            let mut items = Vec::with_capacity(n.min(64) as usize);
            for _ in 0..n {
                items.push(parse(tokens, cursor, depth + 1, limits)?);
            }
            Ok(CborValue::Array(items))
        }
        Token::Map(n) => {
            let n = *n;
            if n > limits.max_items {
                return Err(CborError::TooWide { max: limits.max_items });
            }
            let mut pairs = Vec::with_capacity(n.min(64) as usize);
            for _ in 0..n {
                let k = parse(tokens, cursor, depth + 1, limits)?;
                let v = parse(tokens, cursor, depth + 1, limits)?;
                pairs.push((k, v));
            }
            Ok(CborValue::Map(pairs))
        }
        Token::Tag(tag) => {
            let tag = tag.as_u64();
            let inner = parse(tokens, cursor, depth + 1, limits)?;
            Ok(CborValue::Tag(tag, Box::new(inner)))
        }
        Token::BeginArray => {
            let mut items = Vec::new();
            loop {
                if matches!(tokens.get(*cursor), Some(Token::Break)) {
                    *cursor += 1;
                    break;
                }
                if items.len() as u64 >= limits.max_items {
                    return Err(CborError::TooWide { max: limits.max_items });
                }
                items.push(parse(tokens, cursor, depth + 1, limits)?);
            }
            Ok(CborValue::Array(items))
        }
        Token::BeginMap => {
            let mut pairs = Vec::new();
            loop {
                if matches!(tokens.get(*cursor), Some(Token::Break)) {
                    *cursor += 1;
                    break;
                }
                if pairs.len() as u64 >= limits.max_items {
                    return Err(CborError::TooWide { max: limits.max_items });
                }
                let k = parse(tokens, cursor, depth + 1, limits)?;
                let v = parse(tokens, cursor, depth + 1, limits)?;
                pairs.push((k, v));
            }
            Ok(CborValue::Map(pairs))
        }
        Token::BeginBytes => {
            let mut buf = Vec::new();
            loop {
                match next(tokens, cursor)? {
                    Token::Bytes(b) => {
                        if buf.len().saturating_add(b.len()) > limits.max_bytes {
                            return Err(CborError::TooLarge { len: buf.len() + b.len(), max: limits.max_bytes });
                        }
                        buf.extend_from_slice(b);
                    }
                    Token::Break => break,
                    _ => return Err(CborError::Malformed("indefinite byte string with a non-byte chunk".into())),
                }
            }
            Ok(CborValue::Bytes(buf))
        }
        Token::BeginString => {
            let mut buf = String::new();
            loop {
                match next(tokens, cursor)? {
                    Token::String(s) => {
                        if buf.len().saturating_add(s.len()) > limits.max_bytes {
                            return Err(CborError::TooLarge { len: buf.len() + s.len(), max: limits.max_bytes });
                        }
                        buf.push_str(s);
                    }
                    Token::Break => break,
                    _ => return Err(CborError::Malformed("indefinite text string with a non-text chunk".into())),
                }
            }
            Ok(CborValue::Text(buf))
        }
        // Simple/Undefined/stray Break are valid CBOR but do not occur in engine value encodings;
        // refusing them keeps the accepted surface tight and fail-closed.
        Token::Break => Err(CborError::Malformed("unexpected break".into())),
        Token::Undefined => Err(CborError::Unsupported("undefined")),
        Token::Simple(_) => Err(CborError::Unsupported("simple value")),
    }
}

impl CborValue {
    fn type_name(&self) -> &'static str {
        match self {
            CborValue::Int(_) => "integer",
            CborValue::Bytes(_) => "byte string",
            CborValue::Text(_) => "text string",
            CborValue::Array(_) => "array",
            CborValue::Map(_) => "map",
            CborValue::Bool(_) => "bool",
            CborValue::Null => "null",
            CborValue::Float(_) => "float",
            CborValue::Tag(_, _) => "tag",
        }
    }

    /// An unsigned 64-bit integer, or an incorrect-type error. This is how a reader takes a value
    /// like `minimum_value_promise` without accepting a different CBOR type in its place.
    pub fn as_u64(&self) -> Result<u64, CborError> {
        match self {
            CborValue::Int(i) if *i >= 0 && *i <= u64::MAX as i128 => Ok(*i as u64),
            other => Err(CborError::UnexpectedType { expected: "unsigned integer", found: other.type_name() }),
        }
    }

    pub fn as_bytes(&self) -> Result<&[u8], CborError> {
        match self {
            CborValue::Bytes(b) => Ok(b),
            other => Err(CborError::UnexpectedType { expected: "byte string", found: other.type_name() }),
        }
    }

    pub fn as_text(&self) -> Result<&str, CborError> {
        match self {
            CborValue::Text(s) => Ok(s),
            other => Err(CborError::UnexpectedType { expected: "text string", found: other.type_name() }),
        }
    }

    pub fn as_array(&self) -> Result<&[CborValue], CborError> {
        match self {
            CborValue::Array(a) => Ok(a),
            other => Err(CborError::UnexpectedType { expected: "array", found: other.type_name() }),
        }
    }

    pub fn as_map(&self) -> Result<&[(CborValue, CborValue)], CborError> {
        match self {
            CborValue::Map(m) => Ok(m),
            other => Err(CborError::UnexpectedType { expected: "map", found: other.type_name() }),
        }
    }

    /// Look up a text key in a map, returning the first matching value. `None` if this is not a map
    /// or the key is absent — a reader that needs the key uses `ok_or(...)` to fail closed.
    pub fn get(&self, key: &str) -> Option<&CborValue> {
        match self {
            CborValue::Map(m) => m.iter().find_map(|(k, v)| match k {
                CborValue::Text(s) if s == key => Some(v),
                _ => None,
            }),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests;
