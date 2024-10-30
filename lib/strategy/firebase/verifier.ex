defmodule AshAuthentication.Strategy.Firebase.Verifier do
  @moduledoc """
  DSL verifier for firebase strategies.
  """

  import AshAuthentication.Validations

  def verify(strategy, _dsl_state) do
    validate_secret(strategy, :project_id)
  end
end
