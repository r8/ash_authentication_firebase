# Changelog

## [Unreleased]

### Added

- Dialyzer to CI alongside `mix test`, `mix credo --strict`, and `mix format --check-formatted`
- README "Security model" section enumerating what's verified vs. out of scope (notably token revocation)
- README now includes a complete minimal resource example (identity, `create` action with `upsert?`/`upsert_identity`) and a sign-in-only variant, so users can copy-paste a configuration that passes the strategy's compile-time validation
- DSL options: `registration_enabled?` (default `true`) for authenticating only pre-provisioned users, plus `sign_in_action_name` and `register_action_name` to customize the relevant actions
- DSL option `require_email_verified?` (default `true`) rejecting tokens without a `true` `email_verified` claim
- Structured errors `Errors.EmailNotVerified` and `Errors.InvalidToken` (with a `:reason` field)
- Support for multiple Firebase strategies with different `project_id`s on one resource
- Clock-skew leeway (`clock_skew_leeway_seconds`, default 60s, valid range 0..300)
- Telemetry events for key-store fetches, token rejections, and missing-secret misconfiguration (`[:ash_authentication_firebase, :strategy, :missing_secret]`); missing secrets also now log a distinct `Logger.error` so operators can tell config errors apart from invalid-token traffic
- `uid` now included in the user info map; `token_input` accepts atom or string keys

### Changed

- Register action is now validated at compile time: it must be a `:create` action with `upsert?: true` and an `upsert_identity` set, so repeat sign-ins update the existing user instead of creating duplicates
- Sign-in action (in `registration_enabled?(false)` mode) is now validated at compile time to be a `:read` action; misconfiguring it as a `:create` is a `DslError` instead of a runtime crash
- Key store now reads from `:persistent_term` (lock-free) and refreshes synchronously on a key miss, so the first request after a key rotation no longer fails
- Key-fetch failures retry with jittered exponential backoff (capped at 5 min); refresh debounce shortened to 1s
- Hardened JWKS handling: regex-based `max-age` parsing (case-insensitive, floored at 60s and clamped to 24h), validated response shape, and stricter `project_id` secret validation; non-200 HTTP error bodies are truncated to 500 chars before being logged so a hostile or buggy upstream cannot blow up the log volume
- Bundled `KeyStore` no longer starts when a custom `:key_store` is configured; the bundled Finch pool is now gated on the same condition (previously it was started unconditionally)

### Fixed

- `TokenVerifier.verify/2` no longer crashes on key-store errors, non-binary/empty token or `project_id` arguments, or malformed payloads — these now surface as clean error tuples (`:key_not_found`, `:malformed_payload`, etc.)
- Blank/non-binary secrets correctly produce `MissingSecret`; non-binary or empty token params short-circuit as missing
- Added missing key verifications and pass all token fields to the Ash resource
- `KeyStore` now honors the `:refresh_interval` start option as the fallback when Google's response lacks a parseable `Cache-Control: max-age` header (previously the option was silently ignored)
- `do_sign_in/3` no longer crashes with `CaseClauseError` if `Ash.read/2` ever returns a non-exception `{:error, term}` — such errors are wrapped in `AuthenticationFailed` like other failures
- `KeyStore.refresh_now/0` now catches all `:exit` reasons (`:noproc`, `:killed`, etc.), not just `:timeout`, returning `{:error, :not_started}` or `{:error, {:key_store_exit, reason}}` instead of crashing the caller on the token-verify hot path
- Header parsing now requires `kid` to be a non-empty binary; a non-binary or empty `kid` surfaces as `:invalid_header` (previously degraded to `:key_not_found`)
- `sub` validation now caps length at 128 characters to match Firebase Admin SDK
- `KeyStore` no longer crashes when Google's JWKS response contains a non-binary, empty, or non-PEM value — the bad entry is skipped and the remaining valid keys are loaded
- Invalid `:clock_skew_leeway_seconds` config (non-integer, negative, or > 300) is logged and replaced with the 60s default instead of being used as-is; the resolved value is now cached in `:persistent_term` so an invalid config only logs once per VM lifetime instead of on every verify call

## [1.0.0] - 2026-05-05

### Breaking Changes

- Upgraded to AshAuthentication 4

## [0.2.0] - 2024-10-30

### Added

- Use AshAuthentication.Secret to set Firebase project id

### Fixed

- Return an error from fetcher if no valid keys fetched

## [0.0.1] - 2024-10-29

- Initial release
