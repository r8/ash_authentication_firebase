# AshAuthentication.Firebase

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
      # You can have multiple firebase strategies
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

## Acknowledgements

Inspired by [ExFirebaseAuth](https://github.com/Nickforall/ExFirebaseAuth).
