defmodule AshAuthentication.Strategy.Firebase.Dsl do
  @moduledoc """
  DSL declaration for firebase strategies.
  """
  alias AshAuthentication.Strategy.Firebase
  alias Spark.Dsl.Entity

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
          """,
          required: false
        ]
      ]
    }
  end
end
