# mcpg-sensitive

> Secret-handling primitives: the `Sensitive<T>` newtype and the shared credential redactor.

Two small, dependency-light pieces that keep credentials out of logs, traces,
schemas, and audit records. `Sensitive<T>` wraps a config field so it renders as
`***` in any `Debug` output and cannot be `Display`-formatted at all; the
`redact` module holds the canonical credential-key list, the bare-credential
heuristic, and the JSON walk that scrubs a payload before it reaches a log line,
an SSE stream, or an audit sink. Reach for the wrapper when a struct field holds
a secret, and for the redactor when you are about to emit an arbitrary JSON
payload that a caller may have stuffed a token into.

## What's here

### `Sensitive<T>`

- `Sensitive::new(value)` / `From<T>` to construct; `expose()` borrows the inner
  value and `into_inner_secret()` moves it out. Both are named so a read site is
  greppable as a secret-handling boundary.
- `Debug` prints the `REDACTED_SENTINEL` constant (`***`) and nothing else, so
  `tracing::info!(?config)`, `format!("{:?}", config)`, `dbg!`, and panic
  messages that embed `Debug` output all stay clean.
- **No `Display` impl, deliberately.** `format!("{}", secret)` is a compile
  error; the only way to read the value is the explicit `expose()` call.
- `Deref`, `AsRef`, `Clone`, `PartialEq`, `Eq`, `Hash`, and `Default` pass
  through to the inner type.
- `Serialize`, `Deserialize`, and `JsonSchema` pass through as well, so a
  `Sensitive<String>` deserializes from a plain YAML/JSON string and appears in
  generated JSON Schema as a plain string — the wrapper is invisible to
  operators reading the config reference.

`Serialize` writing the raw value is a deliberate trade: config-rotation tooling
needs to round-trip a loaded config back to YAML. Never serialize a
`Sensitive<T>` into a log sink, a metrics label, or a telemetry attribute.

The wrapper also does not follow a secret once it leaves the type. A value
expanded from `${env.X}` at request time is a plain `String`; if it is stored
back into a field that gets logged, wrap that field too.

### `redact`

- `CREDENTIAL_KEYS` — the canonical, case-insensitive key list
  (`authorization`, `proxy-authorization`, `cookie`, `set-cookie`, `x-api-key`,
  `x-auth-token`, `api_key`, `api-key`, `apikey`, `password`, `secret`, `token`,
  `access_token`, `refresh_token`, `client_secret`).
- `is_credential_key(key)` — case-insensitive membership test.
- `looks_like_credential(s)` — whole-string heuristic: `Bearer` / `Basic` /
  `DPoP` prefixes, known secret prefixes (`sk_`, `pk_`, `AKIA`, `AIza`, `ya29.`,
  `ghp_`, `xoxb-`, `xoxp-`), PEM private-key blocks, and JWT-shaped
  three-segment base64url tokens.
- `redact_credentials_with(value, text_redactor)` — recursive JSON walk. A value
  under a credential key is replaced with `[redacted]` outright; a string leaf
  that looks like a credential is replaced outright; every other string leaf is
  passed through the caller-supplied `text_redactor`, which lets a caller also
  scrub secrets embedded in ordinary strings (URL userinfo, for instance)
  without duplicating the key list or the traversal. Keys, array indices, and
  non-string primitives are preserved so the record stays parseable.

Keeping the list and the walk in one crate is the point: the gateway's outbound
notification scrubber and the audit plugin share this implementation and cannot
drift apart. A test pins `CREDENTIAL_KEYS` to its exact contents so the list
cannot shrink unnoticed.

## Used by

- `apps/gateway` — config fields that hold credentials, and the outbound
  `notifications/message` redactor built on `redact_credentials_with`.
- `mcpg-plugin-observability-audit` — redacts tool arguments and results before
  they reach an audit sink, through the same walk.
- `mcpg-backend-llm-shared` and the LLM backend plugins (`openai`, `anthropic`,
  `gemini`, `compat`, `stability`), plus `mcpg-plugin-backend-sql`.

## Usage

```rust
use mcpg_sensitive::Sensitive;
use serde::Deserialize;

#[derive(Debug, Deserialize)]
struct OAuth {
    client_id: String,
    client_secret: Sensitive<String>,
}

let cfg: OAuth = serde_yaml::from_str(
    "client_id: app123\nclient_secret: super-secret-token\n",
)
.unwrap();

assert_eq!(cfg.client_secret.expose().as_str(), "super-secret-token");
assert_eq!(
    format!("{cfg:?}"),
    r#"OAuth { client_id: "app123", client_secret: *** }"#
);
```

Scrubbing a payload, supplying an identity text redactor when there is nothing
extra to strip from ordinary strings:

```rust
use mcpg_sensitive::redact::redact_credentials_with;
use serde_json::json;

let payload = json!({"authorization": "Bearer abc.def.ghi", "note": "ok"});
let safe = redact_credentials_with(&payload, |s| s.to_owned());

assert_eq!(safe["authorization"], "[redacted]");
assert_eq!(safe["note"], "ok");
```

The crate targets Rust edition 2024.

## Build / test

```bash
cargo build -p mcpg-sensitive
cargo test  -p mcpg-sensitive
```

## Licence

Apache-2.0.

## See also

- [Audit logging](https://mcpg.dev/docs/security/audit)
- [Gateway configuration reference](https://mcpg.dev/docs/reference/configuration)
