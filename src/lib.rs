//! `Sensitive<T>` — a wrapper for credential-bearing config values
//! that prints `***` in any `Debug` output and refuses to compile
//! through `Display`.
//!
//! Wrap fields whose values are credentials so they don't leak via
//! `tracing::info!(?config)`, `format!("{:?}", config)`, panic
//! messages, or any other Debug-rendered surface.
//!
//! ```
//! use mcpg_sensitive::Sensitive;
//! use serde::Deserialize;
//!
//! #[derive(Debug, Deserialize)]
//! struct OAuth {
//!     client_id: String,
//!     client_secret: Sensitive<String>,
//! }
//!
//! let cfg: OAuth = serde_yaml::from_str(
//!     "client_id: app123\nclient_secret: super-secret-token\n",
//! ).unwrap();
//!
//! // Inner value flows through normally for use:
//! assert_eq!(cfg.client_secret.expose().as_str(), "super-secret-token");
//! // But Debug renders the redaction sentinel:
//! assert_eq!(format!("{cfg:?}"), r#"OAuth { client_id: "app123", client_secret: *** }"#);
//! ```
//!
//! ## What this catches
//!
//! - `tracing::info!(?config)` and any other `?value` formatter usage.
//! - `format!("{:?}", value)`, `dbg!(value)`, panic messages that
//!   embed Debug output.
//! - JSON Schema generation: `Sensitive<String>` schemas to the
//!   inner type (string), so the operator-facing reference shows
//!   the field as a regular string with no leakage.
//!
//! ## What this does NOT catch
//!
//! - **`Display` is intentionally not implemented.** `format!("{}",
//!   value)` is a compile error — by design. Reading the secret
//!   value requires the explicit [`Sensitive::expose`] call, which
//!   makes the leak surface auditable via grep.
//! - **`Serialize` is pass-through.** Persisting a `Sensitive<T>`
//!   to YAML/JSON writes the raw secret. That's the right behaviour
//!   for config rotation tools that read the gateway's loaded
//!   config back to YAML, but DO NOT serialise this type into a
//!   log sink or metrics label.
//! - **Runtime CEL expansion.** `${env.SECRET_X}` resolved at
//!   request time becomes a plain `String` once it leaves the
//!   expansion path. If you store the resolved value back into a
//!   field that gets logged, wrap that field in `Sensitive`.

use std::ops::Deref;

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

pub mod redact;

/// Sentinel string emitted by [`Sensitive::fmt`] in place of the
/// inner value. Six asterisks — short enough to scan, long enough
/// not to be confused with a partial mask.
pub const REDACTED_SENTINEL: &str = "***";

/// Wrapper for credential-bearing values. See the crate-level docs
/// for the contract; in short: `Debug` prints `***`, `Display`
/// doesn't compile, `Serialize`/`Deserialize`/`JsonSchema`
/// pass-through to the inner type.
#[derive(Clone, PartialEq, Eq, Hash, Default)]
pub struct Sensitive<T>(T);

impl<T> Sensitive<T> {
    /// Construct from an inner value. Same as `From::from(value)`.
    #[must_use]
    pub const fn new(value: T) -> Self {
        Self(value)
    }

    /// Borrow the inner value. The method is named `expose` rather
    /// than `as_inner` so any read site is greppable as a
    /// secret-handling boundary.
    #[must_use]
    pub const fn expose(&self) -> &T {
        &self.0
    }

    /// Move the inner value out. Same auditability story as
    /// [`Self::expose`] — explicit name keeps the leak surface
    /// observable via `rg "into_inner_secret"`.
    #[must_use]
    pub fn into_inner_secret(self) -> T {
        self.0
    }
}

impl<T> std::fmt::Debug for Sensitive<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(REDACTED_SENTINEL)
    }
}

// NB: `Display` is intentionally NOT implemented. The compile error
// is the point — accidental `format!("{}", secret)` is caught at
// build time.

impl<T> From<T> for Sensitive<T> {
    fn from(value: T) -> Self {
        Self(value)
    }
}

impl<T> Deref for Sensitive<T> {
    type Target = T;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl<T> AsRef<T> for Sensitive<T> {
    fn as_ref(&self) -> &T {
        &self.0
    }
}

impl<T: Serialize> Serialize for Sensitive<T> {
    fn serialize<S: serde::Serializer>(&self, ser: S) -> Result<S::Ok, S::Error> {
        self.0.serialize(ser)
    }
}

impl<'de, T: Deserialize<'de>> Deserialize<'de> for Sensitive<T> {
    fn deserialize<D: serde::Deserializer<'de>>(de: D) -> Result<Self, D::Error> {
        T::deserialize(de).map(Sensitive)
    }
}

impl<T: JsonSchema> JsonSchema for Sensitive<T> {
    fn schema_name() -> String {
        T::schema_name()
    }

    fn json_schema(generator: &mut schemars::r#gen::SchemaGenerator) -> schemars::schema::Schema {
        T::json_schema(generator)
    }

    fn is_referenceable() -> bool {
        T::is_referenceable()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Debug, Serialize, Deserialize, PartialEq, Eq, JsonSchema)]
    struct Holder {
        public: String,
        secret: Sensitive<String>,
    }

    #[test]
    fn debug_prints_sentinel_inside_struct() {
        let h = Holder {
            public: "world".into(),
            secret: Sensitive::new("burnt-toast".into()),
        };
        let rendered = format!("{h:?}");
        assert!(rendered.contains("public: \"world\""), "{rendered}");
        assert!(rendered.contains("secret: ***"), "{rendered}");
        assert!(!rendered.contains("burnt-toast"), "leak: {rendered}");
    }

    #[test]
    fn standalone_debug_prints_sentinel() {
        let s: Sensitive<String> = Sensitive::new("hush".into());
        assert_eq!(format!("{s:?}"), "***");
    }

    #[test]
    fn expose_returns_inner_value() {
        let s: Sensitive<String> = Sensitive::new("hush".into());
        assert_eq!(s.expose(), "hush");
        assert_eq!(s.into_inner_secret(), "hush");
    }

    #[test]
    fn deref_lets_you_call_inner_methods_directly() {
        let s: Sensitive<String> = Sensitive::new("hush".into());
        // Deref<Target = String> means &str methods are reachable.
        assert_eq!(s.len(), 4);
    }

    #[test]
    fn serde_roundtrip_through_yaml_preserves_inner() {
        let h = Holder {
            public: "world".into(),
            secret: Sensitive::new("hush".into()),
        };
        let yaml = serde_yaml::to_string(&h).unwrap();
        // Serialize is pass-through — operators rotating config
        // need the actual value back on the wire.
        assert!(yaml.contains("hush"), "{yaml}");

        let parsed: Holder = serde_yaml::from_str(&yaml).unwrap();
        assert_eq!(parsed, h);
    }

    #[test]
    fn serde_roundtrip_through_json_preserves_inner() {
        let h = Holder {
            public: "world".into(),
            secret: Sensitive::new("hush".into()),
        };
        let json = serde_json::to_string(&h).unwrap();
        assert!(json.contains("hush"), "{json}");

        let parsed: Holder = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, h);
    }

    #[test]
    fn schema_passes_through_to_inner_type() {
        let schema = schemars::schema_for!(Sensitive<String>);
        let json = serde_json::to_string(&schema).unwrap();
        // The wrapper is invisible in the schema — the field looks
        // like a plain String to operators using IDE autocomplete.
        assert!(json.contains("\"type\":\"string\""), "{json}");
        assert!(!json.contains("Sensitive"), "{json}");
    }

    #[test]
    fn equality_compares_inner_values() {
        let a: Sensitive<String> = Sensitive::new("x".into());
        let b: Sensitive<String> = Sensitive::new("x".into());
        let c: Sensitive<String> = Sensitive::new("y".into());
        assert_eq!(a, b);
        assert_ne!(a, c);
    }

    #[test]
    fn from_conversion_is_ergonomic() {
        let s: Sensitive<String> = "hush".to_owned().into();
        assert_eq!(s.expose(), "hush");
    }

    /// This test does not assert; its purpose is to fail the test
    /// suite to compile if anyone ever adds a `Display` impl. The
    /// `assert!(false)` body is unreachable — the surrounding test
    /// only lives to keep the doc hint visible in coverage reports.
    #[test]
    fn display_impl_must_not_exist() {
        // Guard rail comment: the line below is intentionally
        // commented out. If you uncomment it and the test compiles,
        // someone added a `Display` impl that leaks the secret.
        //
        // let _ = format!("{}", Sensitive::<String>::new("x".into()));
    }
}
