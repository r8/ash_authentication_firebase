# AshAuthentication.Firebase

[![Elixir CI](https://github.com/r8/ash_authentication_firebase/actions/workflows/elixir.yml/badge.svg)](https://github.com/r8/ash_authentication_firebase/actions/workflows/elixir.yml)
[![Hex.pm](https://img.shields.io/hexpm/v/ash_authentication_firebase.svg?style=flat-square)](https://hex.pm/packages/ash_authentication_firebase)
[![Hex.pm](https://img.shields.io/hexpm/dt/ash_authentication_firebase.svg?style=flat-square)](https://hex.pm/packages/ash_authentication_firebase)

Firebase token authentication strategy for [AshAuthentication](https://github.com/team-alembic/ash_authentication).

> 🛠 In development. Use at your own risk.

## Requirements

- [AshAuthentication](https://github.com/team-alembic/ash_authentication) ~> 4.0

## Installation

The package can be installed by adding `ash_authentication_firebase` to your list of dependencies in mix.exs:

```elixir
def deps do
  [
    {:ash_authentication_firebase, "~> 1.0.0"}
  ]
end
```

## Usage

Please consult with official [Ash documentation](https://hexdocs.pm/ash_authentication/get-started.html) on how to configure your resource.

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
      # Each strategy verifies tokens against its own project_id (iss/aud claims)
      # and rejects tokens issued for any other project.
      firebase :firebase do
        project_id "project-123abc"
        token_input :firebase_token
      end
    end
  end
...

end
```

### A note on the shared key cache

The library starts a single global `Finch` pool and a single global `KeyStore`
GenServer. This is intentional: Google publishes one shared JWK set for all
Firebase projects at `securetoken@system.gserviceaccount.com`, and keys are
looked up by `kid` — so a per-strategy cache would only duplicate the same
keyring. Per-project `iss`/`aud` enforcement happens during token verification,
not at the cache layer. If you ever need a per-project key source (a custom
auth server, the Firebase Auth emulator, or a non-Google IdP emulating
Firebase), per-strategy `KeyStore`/`Finch` would be required — currently out of
scope.

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

## Handling Google key rotation

When a token arrives with a `kid` that is not in cache (typically right after Google rotates signing keys), the verifier triggers one synchronous `KeyStore` refresh and retries the lookup before failing. Concurrent misses coalesce into a single network fetch via a short recency window, so a burst of unknown-`kid` tokens cannot stampede the upstream endpoint.

## Acknowledgements

Inspired by [ExFirebaseAuth](https://github.com/Nickforall/ExFirebaseAuth).
