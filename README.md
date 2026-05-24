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

## Sharing a Finch pool

By default this library starts its own Finch pool named `AshAuthentication.Firebase.Finch` for fetching Google's public keys. To reuse an existing pool managed by your host application instead, set:

```elixir
config :ash_authentication_firebase, finch_name: MyApp.Finch
```

When this is set, the library will not start its own Finch pool and will route all key-fetch requests through the configured one. Ensure `MyApp.Finch` is started by your host application's supervision tree before `:ash_authentication_firebase` starts.

## Telemetry

The library emits the following `:telemetry` events. Attach handlers to pipe them into your observability stack of choice (Prometheus, StatsD, etc.).

| Event | Measurements | Metadata |
| --- | --- | --- |
| `[:ash_authentication_firebase, :key_store, :fetched]` | `%{retry_attempt, keys_count, expires_in}` | `%{}` |
| `[:ash_authentication_firebase, :key_store, :fetch_failed]` | `%{retry_attempt, delay}` | `%{reason}` |
| `[:ash_authentication_firebase, :strategy, :token_rejected]` | `%{count: 1}` | `%{reason, strategy}` |

- `:fetched` fires after a successful refresh of Google's public keys. `expires_in` is the milliseconds until the next scheduled refresh derived from the response's `Cache-Control: max-age`. `retry_attempt` reports how many failed attempts preceded this success (`0` on the happy path).
- `:fetch_failed` fires whenever a key fetch fails. `delay` is the milliseconds until the next retry; `reason` is the underlying error (a `Mint.TransportError`, an HTTP status string, `:timeout`, `:no_valid_keys`, `:invalid_key_response`, etc.).
- `:token_rejected` fires when token verification fails at the strategy boundary. `reason` is one of the values listed in `AshAuthentication.Firebase.Errors.InvalidToken`'s `t:reason/0` type (e.g. `:invalid_signature`, `:expired`, `:invalid_audience`); `strategy` is the strategy name configured in the DSL.

## Acknowledgements

Inspired by [ExFirebaseAuth](https://github.com/Nickforall/ExFirebaseAuth).
