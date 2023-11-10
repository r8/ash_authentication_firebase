# AshAuthentication.Firebase

[![Hex.pm](https://img.shields.io/hexpm/v/ash_authentication_firebase.svg?style=flat-square)](https://hex.pm/packages/ash_authentication_firebase)
[![Hex.pm](https://img.shields.io/hexpm/dt/ash_authentication_firebase.svg?style=flat-square)](https://hex.pm/packages/ash_authentication_firebase)

Firebase token authentication strategy for [AshAuthentication](https://github.com/team-alembic/ash_authentication).

> 🛠 In development. Use at your own risk.

## Installation

The package can be installed by adding `ash_authentication_firebase` to your list of dependencies in mix.exs:

```elixir
def deps do
  [
    {:ash_authentication_firebase, "~> 0.1.0"}
  ]
end
```

## Configuration

The library uses [ExFirebaseAuth](https://github.com/Nickforall/ExFirebaseAuth) under the hood (subject to change in the next versions), so you'll have to configure it.

Add the Firebase auth issuer name for your project to your `config.exs`:

```elixir
config :ex_firebase_auth, :issuer, "https://securetoken.google.com/project-123abc"
```

## Usage

Please consult with official [Ash documentation](https://ash-hq.org/docs/guides/ash_authentication/latest/tutorials/getting-started-with-authentication) on how to create your resource.

Add `AshAuthentication.Strategy.Firebase` to your resource `extensions` list and `:firebase` strategy to the `authentication` section:

```elixir
defmodule MyApp.Accounts.User do
  use Ash.Resource,
    extensions: [AshAuthentication, AshAuthentication.Strategy.Firebase]

...

  authentication do
    api MyApp.Accounts

    strategies do
      firebase :example do
        token_input :firebase_token
      end
    end
  end

...

end
```
