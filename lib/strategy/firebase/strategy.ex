defimpl AshAuthentication.Strategy, for: AshAuthentication.Strategy.Firebase do
  @moduledoc """
  Authentication protocol implementation for firebase strategies.
  """
  alias Ash.Changeset
  alias Ash.Resource
  alias AshAuthentication.Errors
  alias AshAuthentication.Firebase.TokenVerifier

  import AshAuthentication.Plug.Helpers, only: [store_authentication_result: 2]

  require Ash.Query

  def name(strategy), do: strategy.name

  def tokens_required?(_), do: false

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
    params = Map.take(conn.params, [to_string(strategy.token_input)])

    result = action(strategy, :sign_in, params, [])

    store_authentication_result(conn, result)
  end

  def action(strategy, :sign_in, params, options) do
    action = Resource.Info.action(strategy.resource, strategy.register_action_name, :create)

    with {:ok, project_id} <- fetch_secret(strategy, :project_id),
         {:ok, firebase_token} <-
           get_firebase_token_from_params(params, strategy.token_input),
         {:ok, _token, fields} <- verify_firebase_token(firebase_token, project_id) do
      strategy.resource
      |> Changeset.new()
      |> Changeset.set_context(%{
        private: %{
          ash_authentication?: true
        }
      })
      |> Changeset.for_create(strategy.register_action_name, %{user_info: fields},
        upsert?: true,
        upsert_identity: action.upsert_identity
      )
      |> Ash.create(options)
    else
      _ ->
        {:error, Errors.InvalidToken.exception(type: :sign_in)}
    end
  end

  defp verify_firebase_token(token, project_id) do
    TokenVerifier.verify(token, project_id)
  end

  defp get_firebase_token_from_params(params, token_input) do
    case Map.get(params, token_input) || Map.get(params, Atom.to_string(token_input)) do
      nil -> :error
      token -> {:ok, token}
    end
  end

  defp fetch_secret(strategy, secret_name) do
    path = [:authentication, :strategies, strategy.name, secret_name]

    with {:ok, {secret_module, secret_opts}} <- Map.fetch(strategy, secret_name),
         {:ok, secret} when is_binary(secret) and byte_size(secret) > 0 <-
           secret_module.secret_for(path, strategy.resource, secret_opts, %{}) do
      {:ok, secret}
    else
      {:ok, secret} ->
        {:ok, secret}

      _ ->
        {:error, Errors.MissingSecret.exception(path: path, resource: strategy.resource)}
    end
  end
end
