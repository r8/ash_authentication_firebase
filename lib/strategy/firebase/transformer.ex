defmodule AshAuthentication.Strategy.Firebase.Transformer do
  @moduledoc """
  DSL transformer for firebase strategies.
  """
  alias Ash.Type
  alias AshAuthentication.Strategy
  alias Spark.{Dsl.Transformer, Error.DslError}

  import AshAuthentication.Utils
  import AshAuthentication.Validations
  import AshAuthentication.Validations.Action
  import AshAuthentication.Strategy.Custom.Helpers

  def transform(strategy, dsl_state) do
    with strategy <- set_defaults(strategy),
         :ok <- maybe_validate_register_action(dsl_state, strategy),
         :ok <- maybe_validate_sign_in_action(dsl_state, strategy),
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
          ~w[register_action_name sign_in_action_name]a
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

  # sobelow_skip ["DOS.BinToAtom"]
  defp set_defaults(strategy) do
    strategy
    |> maybe_set_field_lazy(:register_action_name, &:"register_with_#{&1.name}")
    |> maybe_set_field_lazy(:sign_in_action_name, &:"sign_in_with_#{&1.name}")
  end

  defp maybe_validate_register_action(dsl_state, strategy) when strategy.registration_enabled? do
    with {:ok, action} <- validate_action_exists(dsl_state, strategy.register_action_name),
         :ok <- validate_action_has_argument(action, :user_info),
         :ok <- validate_action_argument_option(action, :user_info, :type, [Type.Map, :map]),
         :ok <- validate_action_argument_option(action, :user_info, :allow_nil?, [false]) do
      :ok
    else
      {:error, reason} when is_binary(reason) ->
        {:error, "`#{inspect(strategy.register_action_name)}` action: #{reason}"}

      {:error, reason} ->
        {:error, reason}
    end
  end

  defp maybe_validate_register_action(_dsl_state, _strategy), do: :ok

  defp maybe_validate_sign_in_action(_dsl_state, strategy) when strategy.registration_enabled?,
    do: :ok

  defp maybe_validate_sign_in_action(dsl_state, strategy) do
    with {:ok, action} <- validate_action_exists(dsl_state, strategy.sign_in_action_name),
         :ok <- validate_action_has_argument(action, :user_info),
         :ok <- validate_action_argument_option(action, :user_info, :type, [Type.Map, :map]),
         :ok <- validate_action_argument_option(action, :user_info, :allow_nil?, [false]) do
      :ok
    else
      {:error, reason} when is_binary(reason) ->
        {:error, "`#{inspect(strategy.sign_in_action_name)}` action: #{reason}"}

      {:error, reason} ->
        {:error, reason}
    end
  end
end
