defmodule AshAuthentication.Strategy.Firebase.Transformer do
  @moduledoc """
  DSL transformer for firebase strategies.
  """
  alias AshAuthentication.Strategy
  alias Spark.{Dsl.Transformer, Error.DslError}

  import AshAuthentication.Utils
  import AshAuthentication.Validations
  import AshAuthentication.Strategy.Custom.Helpers

  def transform(strategy, dsl_state) do
    with strategy <- set_defaults(strategy),
         {:ok, resource} <- persisted_option(dsl_state, :module) do
      strategy = %{strategy | resource: resource}

      dsl_state =
        dsl_state
        |> Transformer.replace_entity(
          ~w[authentication strategies]a,
          strategy,
          &(Strategy.name(&1) == strategy.name)
        )
        |> then(fn dsl_state ->
          ~w[register_action_name]a
          |> Enum.map(&Map.get(strategy, &1))
          |> register_strategy_actions(dsl_state, strategy)
        end)

      {:ok, dsl_state}
    else
      {:error, reason} when is_binary(reason) ->
        {:error,
         DslError.exception(path: [:authentication, :strategies, strategy.name], message: reason)}

      {:error, reason} ->
        {:error, reason}
    end
  end

  defp set_defaults(strategy) do
    strategy
    |> maybe_set_field_lazy(:register_action_name, &:"register_with_#{&1.name}")
  end
end
