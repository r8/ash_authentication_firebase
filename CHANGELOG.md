# Changelog

## [1.1.0] - 2026-05-24

### Added

- Firebase token verification hardening: email verification checks, structured token errors, clock-skew leeway, `uid` in user info, and atom/string `token_input` keys
- Support for sign-in-only mode, custom action names, and multiple Firebase strategies per resource
- README examples and security model documentation
- Dialyzer in CI
- Telemetry/logging for key-store activity, token rejection, and missing-secret configuration

### Changed

- Registration/sign-in actions are now validated at compile time
- Key store now uses `:persistent_term`, refreshes synchronously on key misses, retries failed fetches with backoff, and handles key rotation more reliably
- JWKS fetching/parsing and Firebase project configuration validation are stricter
- Bundled key-store/Finch processes are only started when needed

### Fixed

- Token verification now returns clean errors instead of crashing on malformed input, key-store failures, invalid headers/payloads, or bad config
- Missing/blank secrets and invalid token params are handled consistently
- Sign-in failures from Ash are wrapped correctly instead of crashing
- Key-store refresh and JWKS parsing are more defensive
- `sub`, `kid`, and clock-skew config validation now match expected Firebase/security constraints

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
