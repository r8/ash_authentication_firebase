# AshAuthentication.Firebase

[![Elixir CI](https://github.com/r8/ash_authentication_firebase/actions/workflows/elixir.yml/badge.svg)](https://github.com/r8/ash_authentication_firebase/actions/workflows/elixir.yml)
[![Hex.pm](https://img.shields.io/hexpm/v/ash_authentication_firebase.svg?style=flat-square)](https://hex.pm/packages/ash_authentication_firebase)
[![Hex.pm](https://img.shields.io/hexpm/dt/ash_authentication_firebase.svg?style=flat-square)](https://hex.pm/packages/ash_authentication_firebase)

Firebase token authentication strategy for [AshAuthentication](https://github.com/team-alembic/ash_authentication).

## Requirements

- [AshAuthentication](https://github.com/team-alembic/ash_authentication) ~> 4.0

## Installation

The package can be installed by adding `ash_authentication_firebase` to your list of dependencies in mix.exs:

```elixir
def deps do
  [
    {:ash_authentication_firebase, "~> 1.0"}
  ]
end
```

## Usage

Please consult official [Ash documentation](https://hexdocs.pm/ash_authentication/get-started.html) on how to configure your resource.

Add `AshAuthentication.Strategy.Firebase` to your resource `extensions` list and `:firebase` strategy to the `authentication` section:

```elixir
defmodule MyApp.Accounts.User do
  use Ash.Resource,
    extensions: [AshAuthentication, AshAuthentication.Strategy.Firebase]

...

  authentication do
    domain MyApp.Accounts

    strategies do
      # Multiple firebase strategies with different project_ids are supported.
      firebase :firebase do
        project_id "project-123abc"
        token_input :firebase_token
      end
    end
  end
...

end
```

## Secrets and Runtime Configuration

To avoid hardcoding your Firebase project id in your source code, you can use the `AshAuthentication.Secret` behaviour. This allows you to provide the project id through runtime configuration using either an anonymous function or a module.

### Examples:

Using an anonymous function:

```elixir
authentication do
  strategies do
    firebase :firebase do
      project_id fn _path, _resource ->
        Application.fetch_env(:my_app, :firebase_project_id)
      end
      token_input :firebase_token
    end
  end
end
```

Using a module:

```elixir
defmodule MyApp.Secrets do
  use AshAuthentication.Secret

  def secret_for([:authentication, :strategies, :firebase, :project_id], MyApp.Accounts.User, _opts, _context) do
    Application.fetch_env(:my_app, :firebase_project_id)
  end
end

# And in your resource:

authentication do
  strategies do
    firebase :firebase do
      project_id MyApp.Secrets
      token_input :firebase_token
    end
  end
end
```

## Security model

This library performs the [token-verification checks documented by Firebase](https://firebase.google.com/docs/auth/admin/verify-id-tokens):

- **Header**: `alg` is `RS256` and `kid` matches one of Google's currently published public keys.
- **Signature**: the token is signed by the matching key.
- **Claims**: `iss` is `https://securetoken.google.com/<project_id>`, `aud` is `<project_id>`, `sub` is a non-empty string, `exp` is in the future, `iat` and `auth_time` are in the past (each within `:clock_skew_leeway_seconds`, default 60s, valid range `0..300`).
- **Email verification** (when `require_email_verified?` is `true`, the default): tokens whose `email` claim is present and non-empty must also have `email_verified` set to the literal boolean `true`. Tokens without an `email` claim (phone-auth, anonymous) are unaffected.

What this library does **not** verify:

- **Revocation / disabled users.** Firebase ID tokens do not reflect server-side state changes until they expire (up to one hour). If you need immediate logout on password reset, account disablement, or admin ban, layer that check inside your Ash sign-in / register action — e.g. consult a "revoked_at" attribute on the user or call Firebase Admin's [`verifyIdToken(..., checkRevoked = true)`](https://firebase.google.com/docs/auth/admin/manage-sessions#detect_id_token_revocation) from a custom change.
- **Custom claim policies.** All custom claims pass through untouched; enforcing role / tenant constraints based on them is your resource's responsibility.

## Telemetry

The library emits the following `:telemetry` events. Attach handlers to pipe them into your observability stack of choice (Prometheus, StatsD, etc.).

| Event | Measurements | Metadata |
| --- | --- | --- |
| `[:ash_authentication_firebase, :key_store, :fetched]` | `%{retry_attempt, keys_count, expires_in}` | `%{}` |
| `[:ash_authentication_firebase, :key_store, :fetch_failed]` | `%{retry_attempt, delay}` | `%{reason}` |
| `[:ash_authentication_firebase, :strategy, :token_rejected]` | `%{count: 1}` | `%{reason, strategy}` |
| `[:ash_authentication_firebase, :strategy, :missing_secret]` | `%{count: 1}` | `%{strategy, path}` |

- `:fetched` fires after a successful refresh of Google's public keys. `expires_in` is the milliseconds until the next scheduled refresh derived from the response's `Cache-Control: max-age`. `retry_attempt` reports how many failed attempts preceded this success (`0` on the happy path).
- `:fetch_failed` fires whenever a key fetch fails. `delay` is the milliseconds until the next retry; `reason` is the underlying error (a `Mint.TransportError`, an HTTP status string, `:timeout`, `:no_valid_keys`, `:invalid_key_response`, etc.).
- `:token_rejected` fires when token verification fails at the strategy boundary. `reason` is one of the values listed in `AshAuthentication.Firebase.Errors.InvalidToken`'s `t:reason/0` type (e.g. `:invalid_signature`, `:expired`, `:invalid_audience`); `strategy` is the strategy name configured in the DSL.
- `:missing_secret` fires when sign-in fails because a required secret (currently `:project_id`) is unset or resolves to a blank value. `path` is the DSL path of the missing secret; `strategy` is the strategy name. Distinguishes operator misconfiguration from end-user bad-token traffic, which both surface to the client as `InvalidToken`.

## Acknowledgements

Inspired by [ExFirebaseAuth](https://github.com/Nickforall/ExFirebaseAuth).
