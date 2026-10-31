//   Copyright 2026 Ghost Gate contributors
//   SPDX-License-Identifier: MIT

use super::*;

/// Encode a canonical CBOR value with minicbor, as the fixtures' "committee-committed" bytes.
fn enc(build: impl FnOnce(&mut minicbor::Encoder<&mut Vec<u8>>)) -> Vec<u8> {
    let mut buf = Vec::new();
    {
        let mut e = minicbor::Encoder::new(&mut buf);
        build(&mut e);
    }
    buf
}

fn b64(bytes: &[u8]) -> String {
    STANDARD.encode(bytes)
}

/// A representative substate-shaped value: the three authority fields a credential verifier reads
/// off the committed value (resource, floor, ownership key), as a CBOR map.
fn utxo_fixture_bytes() -> Vec<u8> {
    enc(|e| {
        e.map(3).unwrap();
        e.str("resource").unwrap().bytes(&[0xAB; 32]).unwrap();
        e.str("minimum_value_promise").unwrap().u64(10_000_000).unwrap();
        e.str("auth").unwrap();
        e.map(1).unwrap();
        e.str("Key").unwrap().bytes(&[0xCD; 32]).unwrap();
    })
}

#[test]
fn a_committed_value_round_trips_and_its_fields_read_by_exact_type() {
    let bytes = utxo_fixture_bytes();
    let decoded = decode_committed_base64(&b64(&bytes), Limits::default()).unwrap();

    // The committed bytes are preserved verbatim for hashing.
    assert_eq!(decoded.committed_bytes(), &bytes[..]);

    // Fields read by exact type.
    let floor = decoded.value().get("minimum_value_promise").unwrap().as_u64().unwrap();
    assert_eq!(floor, 10_000_000);
    assert_eq!(decoded.value().get("resource").unwrap().as_bytes().unwrap().len(), 32);
    let key = decoded.value().get("auth").unwrap().get("Key").unwrap().as_bytes().unwrap();
    assert_eq!(key, &[0xCD; 32]);
}

#[test]
fn an_incorrect_type_is_refused_not_coerced() {
    let bytes = utxo_fixture_bytes();
    let decoded = decode_committed_base64(&b64(&bytes), Limits::default()).unwrap();
    // The floor is an integer, so asking for bytes (or a map) is an explicit type error.
    assert!(matches!(
        decoded.value().get("minimum_value_promise").unwrap().as_bytes(),
        Err(CborError::UnexpectedType { expected: "byte string", .. })
    ));
    assert!(matches!(decoded.value().as_array(), Err(CborError::UnexpectedType { expected: "array", .. })));
}

#[test]
fn a_non_canonical_encoding_is_preserved_exactly() {
    // `0x18 0x05` is the non-minimal one-byte encoding of unsigned 5. A verifier must hash THESE
    // bytes, not a re-minimised `0x05`. (This is exactly the #3100 committed-value case.)
    let raw = [0x18u8, 0x05];
    let decoded = decode_committed_bytes(&raw, Limits::default()).unwrap();
    assert_eq!(decoded.value(), &CborValue::Int(5));
    assert_eq!(decoded.committed_bytes(), &raw[..], "the non-canonical bytes survive verbatim");
}

#[test]
fn indefinite_length_arrays_and_strings_decode_and_are_preserved() {
    // Indefinite array [_ 1, 2] and indefinite text "hi"+"yo", both legal committed forms.
    let arr = [0x9fu8, 0x01, 0x02, 0xff];
    let decoded = decode_committed_bytes(&arr, Limits::default()).unwrap();
    assert_eq!(decoded.value(), &CborValue::Array(vec![CborValue::Int(1), CborValue::Int(2)]));
    assert_eq!(decoded.committed_bytes(), &arr[..]);

    let text = [0x7fu8, 0x62, b'h', b'i', 0x62, b'y', b'o', 0xff];
    let decoded = decode_committed_bytes(&text, Limits::default()).unwrap();
    assert_eq!(decoded.value(), &CborValue::Text("hiyo".to_string()));
    assert_eq!(decoded.committed_bytes(), &text[..]);
}

#[test]
fn malformed_base64_is_refused() {
    assert_eq!(decode_committed_base64("not valid base64 @@@", Limits::default()), Err(CborError::Base64));
    // Whitespace and a newline are not in the STANDARD alphabet: refused, no leniency.
    assert_eq!(decode_committed_base64("AA==\n", Limits::default()), Err(CborError::Base64));
}

#[test]
fn truncated_cbor_is_refused() {
    let bytes = utxo_fixture_bytes();
    let truncated = &bytes[..bytes.len() - 1];
    assert!(matches!(decode_committed_bytes(truncated, Limits::default()), Err(CborError::Malformed(_))));
}

#[test]
fn trailing_bytes_after_a_complete_value_are_refused() {
    let mut bytes = enc(|e| { e.u64(7).unwrap(); }); // one complete value
    bytes.push(0x00); // a second, stray value
    assert!(matches!(decode_committed_bytes(&bytes, Limits::default()), Err(CborError::TrailingData { .. })));
}

#[test]
fn oversized_input_is_refused_before_parsing() {
    let bytes = enc(|e| { e.bytes(&[0u8; 2048]).unwrap(); });
    let limits = Limits { max_bytes: 512, ..Limits::default() };
    assert!(matches!(decode_committed_bytes(&bytes, limits), Err(CborError::TooLarge { .. })));
    // The base64 entry also refuses an over-long encoded string up front.
    assert!(matches!(decode_committed_base64(&b64(&bytes), limits), Err(CborError::TooLarge { .. })));
}

#[test]
fn excessive_nesting_depth_is_refused() {
    // array[array[array[array[0]]]] — depth 4.
    let bytes = [0x81u8, 0x81, 0x81, 0x81, 0x00];
    let limits = Limits { max_depth: 2, ..Limits::default() };
    assert_eq!(decode_committed_bytes(&bytes, limits), Err(CborError::TooDeep { max: 2 }));
    // The same input is fine under a generous depth.
    assert!(decode_committed_bytes(&bytes, Limits::default()).is_ok());
}

#[test]
fn excessively_wide_collections_are_refused() {
    let bytes = enc(|e| {
        e.array(5).unwrap();
        for i in 0..5u64 { e.u64(i).unwrap(); }
    });
    let limits = Limits { max_items: 4, ..Limits::default() };
    assert_eq!(decode_committed_bytes(&bytes, limits), Err(CborError::TooWide { max: 4 }));
    // An indefinite-length collection is bounded the same way.
    let indef = [0x9fu8, 0x00, 0x01, 0x02, 0x03, 0x04, 0xff];
    assert_eq!(decode_committed_bytes(&indef, limits), Err(CborError::TooWide { max: 4 }));
}

#[test]
fn simple_and_undefined_values_are_refused() {
    // 0xf7 = undefined; 0xe0 = simple(0). Neither occurs in engine value encodings.
    assert_eq!(decode_committed_bytes(&[0xf7], Limits::default()), Err(CborError::Unsupported("undefined")));
    assert_eq!(decode_committed_bytes(&[0xe0], Limits::default()), Err(CborError::Unsupported("simple value")));
}

#[test]
fn a_tagged_value_decodes_to_its_tag_and_inner_value() {
    // Tag 2 (a bignum tag) around a byte string, as a shape test (not semantic interpretation).
    let bytes = enc(|e| { e.tag(minicbor::data::Tag::new(2)).unwrap().bytes(&[0x01, 0x00]).unwrap(); });
    let decoded = decode_committed_bytes(&bytes, Limits::default()).unwrap();
    match decoded.value() {
        CborValue::Tag(2, inner) => assert_eq!(inner.as_bytes().unwrap(), &[0x01, 0x00]),
        other => panic!("expected a tag, got {other:?}"),
    }
}
