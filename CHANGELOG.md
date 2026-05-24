# Changelog

## [Unreleased]

### Added

- DSL options: `registration_enabled?` (default `true`) for authenticating only pre-provisioned users, plus `sign_in_action_name` and `register_action_name` to customize the relevant actions
- DSL option `require_email_verified?` (default `true`) rejecting tokens without a `true` `email_verified` claim
- Structured errors `Errors.EmailNotVerified` and `Errors.InvalidToken` (with a `:reason` field)
- Support for multiple Firebase strategies with different `project_id`s on one resource
- Configurable shared Finch pool (`finch_name`) and clock-skew leeway (`clock_skew_leeway_seconds`, default 60s)
- Telemetry events for key-store fetches and token rejections
- `uid` now included in the user info map; `token_input` accepts atom or string keys

### Changed

- Key store now reads from `:persistent_term` (lock-free) and refreshes synchronously on a key miss, so the first request after a key rotation no longer fails
- Key-fetch failures retry with jittered exponential backoff (capped at 5 min); refresh debounce shortened to 1s
- Hardened JWKS handling: regex-based `max-age` parsing (floored at 60s and clamped to 24h), validated response shape, and stricter `project_id` secret validation
- Bundled `KeyStore` no longer starts when a custom `:key_store` is configured

### Fixed

- `TokenVerifier.verify/2` no longer crashes on key-store errors, non-binary/empty token or `project_id` arguments, or malformed payloads — these now surface as clean error tuples (`:key_not_found`, `:malformed_payload`, etc.)
- Blank/non-binary secrets correctly produce `MissingSecret`; non-binary or empty token params short-circuit as missing
- Added missing key verifications and pass all token fields to the Ash resource
- `KeyStore` now honors the `:refresh_interval` start option as the fallback when Google's response lacks a parseable `Cache-Control: max-age` header (previously the option was silently ignored)
- `KeyStore` no longer crashes when Google's JWKS response contains a non-binary, empty, or non-PEM value — the bad entry is skipped and the remaining valid keys are loaded

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
