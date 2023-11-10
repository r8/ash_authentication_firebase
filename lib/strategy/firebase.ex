defmodule AshAuthentication.Strategy.Firebase do
  @moduledoc """
  AshAuthentication strategy for signing in with Firebase token.
  """
  defstruct name: :firebase,
            token_input: nil,
            register_action_name: nil,
            resource: nil,
            strategy_module: __MODULE__

  alias AshAuthentication.Strategy.Firebase.{Dsl, Transformer, Verifier}

  use AshAuthentication.Strategy.Custom, entity: Dsl.dsl()

  defdelegate transform(strategy, dsl_state), to: Transformer
  defdelegate verify(strategy, dsl_state), to: Verifier
end
