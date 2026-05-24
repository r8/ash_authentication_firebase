defmodule AshAuthentication.Strategy.Firebase.Dsl do
  @moduledoc """
  DSL declaration for firebase strategies.
  """
  alias AshAuthentication.Strategy.Firebase
  alias Spark.Dsl.Entity

  @doc """
  Returns the `Spark.Dsl.Entity` that describes the `firebase` DSL block.

  Wired into `AshAuthentication.Strategy.Firebase` via
  `use AshAuthentication.Strategy.Custom, entity: Dsl.dsl()`, which is how the
  block becomes available inside the `authentication.strategies` section of a
  resource.
  """
  @spec dsl() :: Entity.t()
  def dsl do
    secret_type = AshAuthentication.Dsl.secret_type()
    secret_doc = AshAuthentication.Dsl.secret_doc()

    %Entity{
      name: :firebase,
      describe: "Strategy to sign in with Firebase token.",
      examples: [
        """
        firebase :example do
          project_id "my-firebase-project-id"
          token_input :firebase_token
        end
        """
      ],
      target: Firebase,
      args: [{:optional, :name, :firebase}],
      schema: [
        name: [
          type: :atom,
          doc: """
          Uniquely identifies the strategy.
          """,
          required: true
        ],
        project_id: [
          type: secret_type,
          doc: """
          The Firebase project id to use for token verification. #{secret_doc}
          """,
          required: true
        ],
        token_input: [
          type: :atom,
          doc: """
          The input field to validate users' Firebase token.
          """,
          required: true
        ],
        register_action_name: [
          type: :atom,
          doc: ~S"""
          The name of the action to use to register a user.

          The default is computed from the strategy name eg:
          `register_with_#{name}`.

          Only used when `registration_enabled?` is `true`.
          """,
          required: false
        ],
        sign_in_action_name: [
          type: :atom,
          doc: ~S"""
          The name of the action to use to sign in an existing user.

          The default is computed from the strategy name eg:
          `sign_in_with_#{name}`.

          Only used when `registration_enabled?` is `false`. The action must be
          a read action that accepts a `:user_info` map argument and returns at
          most one user (typically by filtering on the `uid` claim).
          """,
          required: false
        ],
        registration_enabled?: [
          type: :boolean,
          doc: """
          When `true` (default), every successful token verification invokes
          the configured `register_action_name` as an upsert. When `false`,
          invokes `sign_in_action_name` as a read; an unknown token subject
          fails with `AuthenticationFailed` instead of creating a user.

          Set to `false` if users are provisioned out-of-band and the Firebase
          strategy should only authenticate existing accounts.
          """,
          default: true
        ],
        require_email_verified?: [
          type: :boolean,
          doc: """
          When true (default), reject Firebase tokens whose `email` claim is
          present but `email_verified` is not `true`. Tokens without an `email`
          claim (phone-auth, anonymous) are unaffected.

          Set to `false` only if you have an alternative verification flow —
          disabling this allows an attacker to register an account with a
          victim's email and receive an `email_verified: false` token that
          your app would otherwise honor.
          """,
          default: true
        ]
      ]
    }
  end
end
