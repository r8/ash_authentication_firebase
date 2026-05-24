# Changelog

## [Unreleased]

### Added

- DSL option `registration_enabled?` (default `true`) — set to `false` to authenticate only pre-provisioned users
- DSL option `sign_in_action_name` for sign-in-only mode, with sensible default `:sign_in_with_<name>`
- DSL option `register_action_name` to customize the registration action
- DSL option `require_email_verified?` (default `true`) — rejects tokens whose `email_verified` claim is not `true`
- `AshAuthentication.Firebase.Errors.EmailNotVerified` error for unverified-email rejections
- `AshAuthentication.Firebase.Errors.InvalidToken` structured error with a `:reason` field describing the specific verification failure
- Support for multiple Firebase strategies with different `project_id`s on the same resource
- Configurable shared Finch pool via `config :ash_authentication_firebase, finch_name: MyApp.Finch`
- Telemetry events: `[:ash_authentication_firebase, :key_store, :fetched | :fetch_failed]` and `[:ash_authentication_firebase, :strategy, :token_rejected]`
- `uid` is now included in the user info map passed to the Ash action
- `token_input` parameter accepts either atom or string keys

### Changed

- Key store reads now use `:persistent_term` — lock-free and free of GenServer serialization on every authentication
- Synchronous key-store refresh on key miss so the first request after a key rotation no longer fails
- Exponential retry backoff with jitter on key-fetch failures, capped at 5 minutes
- `Cache-Control: max-age` parsing is now regex-based and tolerates quoted values
- Stricter `project_id` secret validation — blank/empty values are treated as missing

### Fixed

- Add missing verifications for Firebase keys
- Pass all token fields to Ash Resource
- `TokenVerifier.verify/2` no longer crashes when the key store returns `:not_initialized` or any other error — it now refreshes once and falls back to `:key_not_found` cleanly
- `TokenVerifier.verify/2` no longer raises a `FunctionClauseError` on non-binary / empty-string token or `project_id` arguments
- `JOSE.JWT.verify_strict/3` exceptions on malformed payloads are now caught and surfaced as `:malformed_payload`
- Blank/non-binary resolved secrets now correctly produce `MissingSecret` instead of silently passing through the `project_id` guard
- `firebase_token` params that are present but non-binary or empty no longer reach the verifier; they short-circuit as a missing token

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
