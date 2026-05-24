defmodule AshAuthentication.Strategy.Firebase.Verifier do
  @moduledoc """
  DSL verifier for firebase strategies.
  """

  import AshAuthentication.Validations

  @doc """
  Verifies that the strategy's `:project_id` is set to a valid secret reference.

  Delegates to `AshAuthentication.Validations.validate_secret/2`, which checks
  the configuration at compile time without resolving the secret. Returns `:ok`
  when the reference is well-formed, or `{:error, Spark.Error.DslError.t()}`
  otherwise. Called automatically by Spark via the strategy's `verify/2`
  delegate.
  """
  @spec verify(AshAuthentication.Strategy.Firebase.t(), map()) :: :ok | {:error, term()}
  def verify(strategy, _dsl_state) do
    validate_secret(strategy, :project_id)
  end
end
