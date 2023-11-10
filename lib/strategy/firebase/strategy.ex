defimpl AshAuthentication.Strategy, for: AshAuthentication.Strategy.Firebase do
  @moduledoc """
  Authentication protocol implementation for firebase strategies.
  """
  alias Ash.Resource
  alias Ash.Changeset
  alias AshAuthentication.Errors

  import AshAuthentication.Plug.Helpers, only: [store_authentication_result: 2]

  require Ash.Query

  def name(strategy), do: strategy.name

  def phases(_), do: [:sign_in]
  def actions(_), do: [:sign_in]

  def routes(strategy) do
    subject_name = AshAuthentication.Info.authentication_subject_name!(strategy.resource)

    [
      {"/#{subject_name}/#{strategy.name}", :sign_in}
    ]
  end

  def method_for_phase(_, :sign_in), do: :post

  def plug(strategy, :sign_in, conn) do
    params = Map.take(conn.params, ["firebase_token"])

    result = action(strategy, :sign_in, params, [])

    store_authentication_result(conn, result)
  end

  def action(strategy, :sign_in, params, options) do
    api = AshAuthentication.Info.authentication_api!(strategy.resource)
    action = Resource.Info.action(strategy.resource, strategy.register_action_name, :create)

    with {:ok, firebase_token} <-
           get_firebase_token_from_params(params, strategy.token_input),
         {:ok, _, fields} <- verify_firebase_token(firebase_token),
         user_info <- get_user_info(fields) do
      strategy.resource
      |> Changeset.new()
      |> Changeset.set_context(%{
        private: %{
          ash_authentication?: true
        }
      })
      |> Changeset.for_create(strategy.register_action_name, %{user_info: user_info},
        upsert?: true,
        upsert_identity: action.upsert_identity
      )
      |> api.create(options)
    else
      _ ->
        {:error, Errors.InvalidToken.exception(type: :sign_in)}
    end
  end

  defp verify_firebase_token(token) do
    ExFirebaseAuth.Token.verify_token(token)
  end

  defp get_user_info(%{fields: fields}) do
    Map.take(fields, ["user_id", "email"])
  end

  defp get_firebase_token_from_params(params, token_input) do
    cond do
      Map.has_key?(params, token_input) -> Map.fetch(params, token_input)
      true -> Map.fetch(params, token_input |> Atom.to_string())
    end
  end
end
