defmodule AshAuthentication.Strategy.Firebase.Dsl do
  @moduledoc """
  DSL declaration for firebase strategies.
  """
  alias AshAuthentication.Strategy.Firebase
  alias Spark.Dsl.Entity

  def dsl do
    %Entity{
      name: :firebase,
      describe: "Strategy to sign in with Firebase token.",
      examples: [
        """
        firebase :example do
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
          The strategy name.
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
