//! Masked-secret substitution in HTTP headers.
//!
//! The guest only ever holds a surrogate for a masked `[env]` variable. For
//! rules that `inject` it, the proxy swaps the surrogate for the real value
//! in outbound request header values (before Lua middleware runs) and swaps
//! the real value back to the surrogate in response header values (after
//! Lua middleware has run), so the real secret never crosses into the VM.
//!
//! Rewriting is a byte-level search/replace over every header value —
//! including repeated headers, `cookie`, `host` and friends — and touches
//! nothing else (names, URI, body).

use hyper::header::{HeaderMap, HeaderValue};

use crate::network::target::InjectedSecret;

/// Request direction: surrogate → real.
pub fn unmask_request(headers: &mut HeaderMap, secrets: &[InjectedSecret]) -> anyhow::Result<()> {
    rewrite_headers(headers, &unmask_pairs(secrets))
}

/// Response direction: real → surrogate.
pub fn mask_response(headers: &mut HeaderMap, secrets: &[InjectedSecret]) -> anyhow::Result<()> {
    rewrite_headers(headers, &mask_pairs(secrets))
}

/// Replace every real value in free-form `text` with its surrogate. Used
/// for anything that is about to cross into the guest but is not a header
/// — e.g. the body of an error response, which may quote a request header
/// that was already unmasked.
pub fn mask_text(text: &str, secrets: &[InjectedSecret]) -> String {
    let mut current = text.as_bytes().to_vec();
    for (from, to) in mask_pairs(secrets) {
        if from.is_empty() {
            continue;
        }
        if let Some(replaced) = replace_bytes(&current, from, to) {
            current = replaced;
        }
    }
    String::from_utf8_lossy(&current).into_owned()
}

fn unmask_pairs(secrets: &[InjectedSecret]) -> Vec<(&[u8], &[u8])> {
    ordered_pairs(
        secrets
            .iter()
            .map(|s| (s.surrogate.as_bytes(), s.real.as_bytes())),
    )
}

fn mask_pairs(secrets: &[InjectedSecret]) -> Vec<(&[u8], &[u8])> {
    ordered_pairs(
        secrets
            .iter()
            .map(|s| (s.real.as_bytes(), s.surrogate.as_bytes())),
    )
}

/// Longest needle first. When one secret's value contains another's
/// (`AUTH_HEADER = "Bearer ${TOKEN}"` next to `TOKEN`), rewriting the
/// shorter one first would destroy the longer match and leave the rest of
/// the longer value in place; replacing the longer one first makes the
/// result independent of `inject` list order.
fn ordered_pairs<'a>(
    pairs: impl Iterator<Item = (&'a [u8], &'a [u8])>,
) -> Vec<(&'a [u8], &'a [u8])> {
    let mut pairs: Vec<_> = pairs.collect();
    pairs.sort_by_key(|(from, _)| std::cmp::Reverse(from.len()));
    pairs
}

/// Replace every occurrence of each `from` with its `to` in every header
/// value, in the given order. Empty `from` needles are skipped. A header
/// value is only rebuilt when something actually matched; if the rebuilt
/// bytes are not a valid header value the error names the header but never
/// its content.
pub fn rewrite_headers(headers: &mut HeaderMap, pairs: &[(&[u8], &[u8])]) -> anyhow::Result<()> {
    if pairs.is_empty() {
        return Ok(());
    }
    for (name, value) in headers.iter_mut() {
        let mut current: Option<Vec<u8>> = None;
        for (from, to) in pairs {
            if from.is_empty() {
                continue;
            }
            let haystack: &[u8] = current.as_deref().unwrap_or(value.as_bytes());
            if let Some(replaced) = replace_bytes(haystack, from, to) {
                current = Some(replaced);
            }
        }
        if let Some(bytes) = current {
            *value = HeaderValue::from_bytes(&bytes)
                .map_err(|_| anyhow::anyhow!("header `{name}`: rewritten value is not valid"))?;
        }
    }
    Ok(())
}

/// Replace all non-overlapping occurrences of `needle` in `haystack`.
/// Returns `None` when nothing matched so callers can skip re-allocation.
fn replace_bytes(haystack: &[u8], needle: &[u8], replacement: &[u8]) -> Option<Vec<u8>> {
    debug_assert!(!needle.is_empty());
    let mut out: Option<Vec<u8>> = None;
    let mut last = 0;
    let mut i = 0;
    while i + needle.len() <= haystack.len() {
        if &haystack[i..i + needle.len()] == needle {
            let out = out.get_or_insert_with(|| Vec::with_capacity(haystack.len()));
            out.extend_from_slice(&haystack[last..i]);
            out.extend_from_slice(replacement);
            i += needle.len();
            last = i;
        } else {
            i += 1;
        }
    }
    let mut out = out?;
    out.extend_from_slice(&haystack[last..]);
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn secret(name: &str, real: &str, surrogate: &str) -> InjectedSecret {
        InjectedSecret::new(crate::project::MaskedSecret {
            name: name.into(),
            real: real.into(),
            surrogate: surrogate.into(),
        })
    }

    fn headers(entries: &[(&str, &str)]) -> HeaderMap {
        let mut h = HeaderMap::new();
        for (k, v) in entries {
            h.append(
                hyper::header::HeaderName::from_bytes(k.as_bytes()).unwrap(),
                HeaderValue::from_str(v).unwrap(),
            );
        }
        h
    }

    fn values(h: &HeaderMap, name: &str) -> Vec<String> {
        h.get_all(name)
            .iter()
            .map(|v| v.to_str().unwrap().to_string())
            .collect()
    }

    #[test]
    fn replace_bytes_handles_multiple_and_adjacent_matches() {
        assert_eq!(replace_bytes(b"abcabc", b"abc", b"X"), Some(b"XX".to_vec()));
        assert_eq!(
            replace_bytes(b"xx-abc-yy-abc", b"abc", b"LONGER"),
            Some(b"xx-LONGER-yy-LONGER".to_vec())
        );
        assert_eq!(replace_bytes(b"nothing", b"abc", b"X"), None);
        assert_eq!(replace_bytes(b"", b"abc", b"X"), None);
    }

    #[test]
    fn unmask_request_replaces_surrogate_everywhere() {
        let s = secret("TOKEN", "real-token-value", "SURROGATE1234567");
        let mut h = headers(&[
            ("authorization", "Bearer SURROGATE1234567"),
            ("x-other", "untouched"),
            ("cookie", "a=SURROGATE1234567; b=SURROGATE1234567"),
        ]);
        unmask_request(&mut h, &[s]).unwrap();
        assert_eq!(values(&h, "authorization"), ["Bearer real-token-value"]);
        assert_eq!(values(&h, "x-other"), ["untouched"]);
        assert_eq!(
            values(&h, "cookie"),
            ["a=real-token-value; b=real-token-value"]
        );
    }

    #[test]
    fn mask_response_replaces_real_value() {
        let s = secret("TOKEN", "real-token-value", "SURROGATE1234567");
        let mut h = headers(&[("x-echo", "got real-token-value back")]);
        mask_response(&mut h, &[s]).unwrap();
        assert_eq!(values(&h, "x-echo"), ["got SURROGATE1234567 back"]);
    }

    #[test]
    fn repeated_header_names_are_all_rewritten() {
        let s = secret("TOKEN", "real-token-value", "SURROGATE1234567");
        let mut h = headers(&[
            ("x-multi", "SURROGATE1234567"),
            ("x-multi", "prefix SURROGATE1234567"),
        ]);
        unmask_request(&mut h, &[s]).unwrap();
        assert_eq!(
            values(&h, "x-multi"),
            ["real-token-value", "prefix real-token-value"]
        );
    }

    #[test]
    fn multiple_secrets_apply_in_one_pass() {
        let a = secret("A", "real-a-value-1", "SURR-A-VALUE-1");
        let b = secret("B", "real-b-value-2", "SURR-B-VALUE-2");
        let mut h = headers(&[("x-both", "SURR-A-VALUE-1 and SURR-B-VALUE-2")]);
        unmask_request(&mut h, &[a, b]).unwrap();
        assert_eq!(values(&h, "x-both"), ["real-a-value-1 and real-b-value-2"]);
    }

    #[test]
    fn nested_secrets_mask_the_longer_value_regardless_of_order() {
        // AUTH's real value contains TOKEN's real value. Listing TOKEN first
        // must not leave "Bearer " + surrogate(TOKEN) behind for AUTH.
        let token = secret("TOKEN", "real-token-value", "SURROGATE1234567");
        let auth = secret("AUTH", "Bearer real-token-value", "SURROGATEabcdefghijklmn");
        for order in [vec![token.clone(), auth.clone()], vec![auth, token]] {
            let mut h = headers(&[("x-echo", "got Bearer real-token-value back")]);
            mask_response(&mut h, &order).unwrap();
            assert_eq!(values(&h, "x-echo"), ["got SURROGATEabcdefghijklmn back"]);
        }
    }

    #[test]
    fn non_ascii_real_value_round_trips_through_headers() {
        // Real value is 18 bytes of UTF-8, surrogate is 15 ASCII bytes.
        // Both directions must rewrite by bytes, and the rebuilt header
        // must accept the non-ASCII bytes (HTTP allows 128..=255).
        let s = secret("TOKEN", "🔑-secret-token", "SURROGATEabcdef");
        let mut h = headers(&[("authorization", "Bearer SURROGATEabcdef")]);
        unmask_request(&mut h, std::slice::from_ref(&s)).unwrap();
        assert_eq!(
            h.get("authorization").unwrap().as_bytes(),
            "Bearer 🔑-secret-token".as_bytes()
        );

        let mut h = HeaderMap::new();
        h.insert(
            "x-echo",
            HeaderValue::from_bytes("got 🔑-secret-token back".as_bytes()).unwrap(),
        );
        mask_response(&mut h, &[s]).unwrap();
        assert_eq!(values(&h, "x-echo"), ["got SURROGATEabcdef back"]);
    }

    #[test]
    fn mask_text_replaces_real_values_in_free_text() {
        let s = secret("TOKEN", "real-token-value", "SURROGATE1234567");
        let out = mask_text("middleware error: bad auth: Bearer real-token-value", &[s]);
        assert_eq!(out, "middleware error: bad auth: Bearer SURROGATE1234567");
        assert_eq!(mask_text("nothing here", &[]), "nothing here");
    }

    #[test]
    fn no_secrets_and_empty_needles_are_noops() {
        let mut h = headers(&[("x", "value")]);
        unmask_request(&mut h, &[]).unwrap();
        let empty = secret("E", "", "");
        unmask_request(&mut h, &[empty]).unwrap();
        assert_eq!(values(&h, "x"), ["value"]);
    }

    #[test]
    fn invalid_rewritten_value_errors_without_leaking() {
        // A real value containing a CR/LF can't be a header value.
        let s = secret("TOKEN", "bad\r\nvalue-secret", "SURROGATE1234567");
        let mut h = headers(&[("authorization", "SURROGATE1234567")]);
        let err = unmask_request(&mut h, &[s]).unwrap_err().to_string();
        assert!(err.contains("authorization"), "got: {err}");
        assert!(!err.contains("value-secret"), "leaked: {err}");
    }
}
