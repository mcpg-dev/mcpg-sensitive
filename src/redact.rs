//! Shared credential redactor: the canonical credential-key list, the
//! bare-credential heuristic, and the JSON walk that scrubs them.
//!
//! The gateway's outbound-notification scrubber and the audit plugin both
//! redact request/response payloads before they reach a log, an SSE
//! stream, or an audit sink. Keeping the key list and the walk here means
//! the two surfaces share one implementation and cannot drift apart.
//!
//! The walk is parameterised by a `text_redactor` applied to every
//! non-credential string leaf, so a caller can additionally scrub secrets
//! embedded in otherwise-ordinary strings (e.g. `scheme://user:pass@host`
//! URL userinfo) without duplicating the key list or the traversal.

use serde_json::Value;

/// Canonical credential key list (case-insensitive). A value stored under
/// any of these keys is replaced with `[redacted]`, and a header carrying
/// any of these names is withheld from backend passthrough.
pub const CREDENTIAL_KEYS: &[&str] = &[
    "authorization",
    "proxy-authorization",
    "cookie",
    "set-cookie",
    "x-api-key",
    "x-auth-token",
    "api_key",
    "api-key",
    "apikey",
    "password",
    "secret",
    "token",
    "access_token",
    "refresh_token",
    "client_secret",
];

/// True when `key` names a credential-bearing field (case-insensitive
/// match against [`CREDENTIAL_KEYS`]).
pub fn is_credential_key(key: &str) -> bool {
    CREDENTIAL_KEYS
        .iter()
        .any(|needle| key.eq_ignore_ascii_case(needle))
}

/// Heuristic: does this whole string look like a bare credential — a
/// bearer/basic/DPoP token, a known secret prefix, a PEM private key, or a
/// JWT-shaped three-segment token?
pub fn looks_like_credential(s: &str) -> bool {
    let lower = s.trim_start().to_ascii_lowercase();
    if lower.starts_with("bearer ") || lower.starts_with("basic ") || lower.starts_with("dpop ") {
        return true;
    }
    if s.starts_with("sk_")
        || s.starts_with("pk_")
        || s.starts_with("AKIA")
        || s.starts_with("AIza")
        || s.starts_with("ya29.")
        || s.starts_with("ghp_")
        || s.starts_with("xoxb-")
        || s.starts_with("xoxp-")
    {
        return true;
    }
    if s.contains("-----BEGIN ") && s.contains(" PRIVATE KEY-----") {
        return true;
    }
    // JWT-ish three-segment base64url structure.
    if s.matches('.').count() == 2 {
        let segs: Vec<&str> = s.split('.').collect();
        if segs.iter().all(|seg| {
            !seg.is_empty()
                && seg
                    .chars()
                    .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_' || c == '=')
        }) && segs[0].len() >= 8
            && segs[1].len() >= 8
        {
            return true;
        }
    }
    false
}

/// Recursively walk a JSON value, replacing any credential-shaped string
/// with `[redacted]`. A value under a [`CREDENTIAL_KEYS`] key is redacted
/// outright; a string leaf that [`looks_like_credential`] is redacted
/// outright; every other string leaf is passed through `text_redactor`
/// (identity if the caller has nothing extra to scrub). Keys, array
/// indices, and non-string primitives are preserved so the record stays
/// parseable.
pub fn redact_credentials_with<F>(value: &Value, text_redactor: F) -> Value
where
    F: Fn(&str) -> String + Copy,
{
    match value {
        Value::Object(map) => {
            let mut out = serde_json::Map::with_capacity(map.len());
            for (k, v) in map {
                let next = if is_credential_key(k) {
                    Value::String("[redacted]".to_owned())
                } else {
                    redact_credentials_with(v, text_redactor)
                };
                out.insert(k.clone(), next);
            }
            Value::Object(out)
        }
        Value::Array(items) => Value::Array(
            items
                .iter()
                .map(|v| redact_credentials_with(v, text_redactor))
                .collect(),
        ),
        Value::String(s) => {
            if looks_like_credential(s) {
                Value::String("[redacted]".to_owned())
            } else {
                Value::String(text_redactor(s))
            }
        }
        other => other.clone(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn identity(s: &str) -> String {
        s.to_owned()
    }

    #[test]
    fn canonical_key_set_is_frozen() {
        assert_eq!(
            CREDENTIAL_KEYS,
            &[
                "authorization",
                "proxy-authorization",
                "cookie",
                "set-cookie",
                "x-api-key",
                "x-auth-token",
                "api_key",
                "api-key",
                "apikey",
                "password",
                "secret",
                "token",
                "access_token",
                "refresh_token",
                "client_secret",
            ]
        );
    }

    #[test]
    fn credential_key_match_is_case_insensitive() {
        assert!(is_credential_key("Authorization"));
        assert!(is_credential_key("X-API-KEY"));
        assert!(!is_credential_key("user_id"));
    }

    #[test]
    fn redacts_value_under_credential_key() {
        let v = json!({"authorization": "Bearer abc.def.ghi", "other": "ok"});
        let r = redact_credentials_with(&v, identity);
        assert_eq!(r["authorization"], "[redacted]");
        assert_eq!(r["other"], "ok");
    }

    #[test]
    fn redacts_bearer_value_under_neutral_key() {
        let v = json!({"note": "Bearer abcdef0123456789abcdef"});
        let r = redact_credentials_with(&v, identity);
        assert_eq!(r["note"], "[redacted]");
    }

    #[test]
    fn redacts_jwt_like_string() {
        let v = json!("eyJhbGciOi.eyJzdWIiOi.signaturepart");
        assert_eq!(redact_credentials_with(&v, identity), json!("[redacted]"));
    }

    #[test]
    fn text_redactor_applied_to_ordinary_leaves() {
        let v = json!({"note": "connect nats://user:secret@host:4222 ok"});
        let scrub = |s: &str| s.replace("user:secret@", "");
        let r = redact_credentials_with(&v, scrub);
        assert_eq!(r["note"], "connect nats://host:4222 ok");
    }

    #[test]
    fn recurses_into_arrays_and_nested_objects() {
        let v = json!({"events": [{"token": "Bearer xxx"}, {"msg": "normal"}]});
        let r = redact_credentials_with(&v, identity);
        assert_eq!(r["events"][0]["token"], "[redacted]");
        assert_eq!(r["events"][1]["msg"], "normal");
    }
}
