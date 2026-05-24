defmodule AshAuthentication.Strategy.Firebase do
  @moduledoc """
  AshAuthentication strategy for signing in with Firebase token.
  """
  defstruct __spark_metadata__: nil,
            name: :firebase,
            project_id: nil,
            token_input: nil,
            register_action_name: nil,
            sign_in_action_name: nil,
            registration_enabled?: true,
            require_email_verified?: true,
            resource: nil,
            strategy_module: __MODULE__

  @type t :: %__MODULE__{
          __spark_metadata__: term(),
          name: atom(),
          project_id: {module(), Keyword.t()} | nil,
          token_input: atom() | nil,
          register_action_name: atom() | nil,
          sign_in_action_name: atom() | nil,
          registration_enabled?: boolean(),
          require_email_verified?: boolean(),
          resource: module() | nil,
          strategy_module: module()
        }

  alias AshAuthentication.Strategy.Firebase.{Dsl, Transformer, Verifier}

  use AshAuthentication.Strategy.Custom, entity: Dsl.dsl()

  defdelegate transform(strategy, dsl_state), to: Transformer
  defdelegate verify(strategy, dsl_state), to: Verifier
end
