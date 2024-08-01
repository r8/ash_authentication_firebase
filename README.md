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
      # You can have multiple firebase strategies
      firebase :firebase_prod do
        project_id "project-123abc"
        token_input :firebase_token
      end

      firebase :firebase_staging do
        project_id "project-456def"
        token_input :firebase_token
      end
    end
  end

...

end
```
