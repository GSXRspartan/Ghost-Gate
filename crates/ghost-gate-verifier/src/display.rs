//   Copyright 2026 Ghost Gate contributors
//   SPDX-License-Identifier: MIT

//! Rendering a raw amount the way a person would write it.
//!
//! Every amount Ghost Gate handles is an integer in the resource's own smallest unit, and every
//! comparison it makes is on that integer. Divisibility is therefore never part of a rule -- it only
//! decides how many decimal places to print. Keeping the two in separate modules is the point: a
//! rounding error here can make a screen wrong, and can never make a gate accept.
//!
//! Nothing in this module is a security boundary, and nothing in it is safe to feed back into a
//! threshold. Use [`format_amount`] for humans; use the raw `u64` for everything else.

/// How a symbol was obtained, which a UI should be able to tell the user about.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Symbol {
    /// Resolved from chain by the site, from the resource's own metadata.
    Resolved(String),
    /// The site has no symbol for this resource. Not an error: the resource address is the identity
    /// and everything still works. A gate on an asset nobody has labelled renders bare numbers.
    Unknown,
}

impl Symbol {
    /// The text to render beside an amount.
    pub fn or_unknown(&self) -> &str {
        match self {
            Self::Resolved(s) => s.as_str(),
            Self::Unknown => "",
        }
    }
}

/// Formats `amount` with `divisibility` decimal places, grouping thousands.
///
/// `divisibility` is clamped to 18, the largest a `u64` can be divided into without losing a digit.
/// A resource claiming more is formatted at 18 rather than silently producing a wrong number.
pub fn format_amount(amount: u64, divisibility: u8) -> String {
    let places = u32::from(divisibility.min(18));
    let digits = amount.to_string();
    if places == 0 {
        return group(&digits);
    }
    if digits.len() <= places as usize {
        // Smaller than one whole unit: pad so the reader sees "0.05", not ".05".
        let padding = places as usize - digits.len();
        let mut out = String::with_capacity(digits.len() + padding + 3);
        out.push_str("0.");
        for _ in 0..padding {
            out.push('0');
        }
        out.push_str(&digits);
        return out;
    }
    let split = digits.len() - places as usize;
    format!("{}.{}", group(&digits[..split]), &digits[split..])
}

/// Formats `amount` and appends the symbol when there is one.
///
/// The raw number is deliberately still recoverable: [`format_amount`] is what a screen shows, and a
/// careful user or a debugging session may want to compare it against what consensus saw. Round-trip
/// correctness is checked by the tests rather than assumed.
pub fn format_with_symbol(amount: u64, divisibility: u8, symbol: &Symbol) -> String {
    let number = format_amount(amount, divisibility);
    match symbol {
        Symbol::Resolved(s) => format!("{number} {s}"),
        Symbol::Unknown => number,
    }
}

/// The exact text a threshold should be rendered as, plus the raw value it came from.
///
/// A gate publishes both `threshold` and `divisibility`, so a site can show
/// `>= 1,000,000 GHOSTTEST` and a user can verify the gate really means the number on screen. The
/// raw value is returned rather than reparsed from the text, because reparsing is how a display bug
/// becomes a threshold bug.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RenderedAmount {
    /// The exact raw integer consensus compares.
    pub raw: u64,
    /// Human text, for a screen.
    pub display: String,
}

/// Renders a threshold from what the gate itself published.
pub fn render_threshold(threshold: u64, divisibility: u8, symbol: &Symbol) -> RenderedAmount {
    RenderedAmount {
        raw: threshold,
        display: format_with_symbol(threshold, divisibility, symbol),
    }
}

/// Inserts a separator every three digits, counted from the right.
fn group(digits: &str) -> String {
    let n = digits.len();
    if n <= 3 {
        return digits.to_string();
    }
    let mut out = String::with_capacity(n + n / 3);
    for (i, c) in digits.bytes().enumerate() {
        // A separator belongs where the digits to its right are a whole number of groups.
        if i > 0 && (n - i) % 3 == 0 {
            out.push(',');
        }
        out.push(char::from(c));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    const SYMBOL: Symbol = Symbol::Unknown;

    /// A resolved symbol, which owns its text.
    fn sym(s: &str) -> Symbol {
        Symbol::Resolved(s.to_string())
    }

    #[test]
    fn an_indivisible_resource_renders_a_whole_number() {
        assert_eq!(format_amount(1_000_000, 0), "1,000,000");
        assert_eq!(format_amount(7, 0), "7");
        assert_eq!(format_amount(999, 0), "999");
    }

    #[test]
    fn divisibility_places_the_decimal_point() {
        assert_eq!(format_amount(1_000_000, 6), "1.000000");
        assert_eq!(format_amount(1_000_000, 2), "10,000.00");
        assert_eq!(format_amount(100, 2), "1.00");
        assert_eq!(format_amount(1_000, 2), "10.00");
    }

    #[test]
    fn a_sub_unit_amount_is_padded_not_truncated() {
        assert_eq!(format_amount(5, 6), "0.000005");
        assert_eq!(format_amount(50, 2), "0.50");
        assert_eq!(format_amount(1, 3), "0.001");
        // The failure this guards: "0.05" rendered as ".05" or, worse, as "0.5".
        assert_eq!(format_amount(5, 2), "0.05");
    }

    #[test]
    fn two_assets_with_different_divisibility_render_differently_and_say_the_same_thing() {
        // One tTARI is a million microtari; a divisibility-2 asset divides by a hundred. Same raw
        // integer, two honest renderings, and neither is the other's number.
        assert_eq!(format_with_symbol(1_000_000, 6, &sym("tTARI")), "1.000000 tTARI");
        assert_eq!(format_with_symbol(1_000_000, 2, &sym("GHOSTTEST")), "10,000.00 GHOSTTEST");
        // 10,000 raw units of a divisibility-2 asset is one hundred whole units.
        assert_eq!(format_amount(10_000, 2), "100.00");
        assert_eq!(format_amount(10_000, 0), "10,000");
    }

    #[test]
    fn an_unresolved_symbol_renders_the_number_alone() {
        assert_eq!(format_with_symbol(42_000, 0, &SYMBOL), "42,000");
        assert_eq!(SYMBOL.or_unknown(), "");
        assert_eq!(sym("X").or_unknown(), "X");
    }

    #[test]
    fn a_divisibility_larger_than_a_u64_can_render_is_clamped() {
        // 18 is the most decimal places a u64 can carry: u64::MAX is 18.446744073709551615 in those
        // units. A resource claiming more is rendered at 18 rather than producing a wrong number.
        assert_eq!(format_amount(u64::MAX, 18), "18.446744073709551615");
        assert_eq!(format_amount(u64::MAX, 255), format_amount(u64::MAX, 18));
        // Ten decimal places, the common case, and a value with nothing above the point at all.
        assert_eq!(format_amount(123_456_789_012, 10), "12.3456789012");
        assert_eq!(format_amount(1, 0), "1");
    }

    #[test]
    fn a_rendered_threshold_keeps_the_raw_value_consensus_saw() {
        let rendered = render_threshold(1_000_000, 6, &sym("tTARI"));
        assert_eq!(rendered.raw, 1_000_000);
        assert_eq!(rendered.display, "1.000000 tTARI");
        // The raw value is carried, not reparsed from the text: a display change cannot move it.
        assert_eq!(render_threshold(rendered.raw, 0, &Symbol::Unknown).raw, rendered.raw);
    }

    #[test]
    fn grouping_is_correct_at_every_width() {
        assert_eq!(group(""), "");
        assert_eq!(group("1"), "1");
        assert_eq!(group("12"), "12");
        assert_eq!(group("123"), "123");
        assert_eq!(group("1234"), "1,234");
        assert_eq!(group("12345"), "12,345");
        assert_eq!(group("123456"), "123,456");
        assert_eq!(group("1234567"), "1,234,567");
    }
}