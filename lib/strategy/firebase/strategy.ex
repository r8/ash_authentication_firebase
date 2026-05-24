defimpl AshAuthentication.Strategy, for: AshAuthentication.Strategy.Firebase do
  @moduledoc """
  Authentication protocol implementation for firebase strategies.
  """
  alias Ash.{Changeset, Query, Resource}
  alias AshAuthentication.Errors
  alias AshAuthentication.Errors.AuthenticationFailed
  alias AshAuthentication.Firebase.Errors.{EmailNotVerified, InvalidToken}
  alias AshAuthentication.Firebase.TokenVerifier

  import AshAuthentication.Plug.Helpers, only: [store_authentication_result: 2]

  require Ash.Query
  require Logger

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

    result = action(strategy, :sign_in, params, context: %{conn: conn})

    store_authentication_result(conn, result)
  end

  def action(strategy, :sign_in, params, options) do
    context = Keyword.get(options, :context, %{})

    with {:ok, project_id} <- fetch_secret(strategy, :project_id, context),
         {:ok, firebase_token} <-
           get_firebase_token_from_params(params, strategy.token_input),
         {:ok, uid, fields} <- verify_firebase_token(firebase_token, project_id),
         :ok <- check_email_verified(strategy, fields) do
      user_info = build_user_info(fields, uid)

      if strategy.registration_enabled? do
        do_register(strategy, user_info, options)
      else
        do_sign_in(strategy, user_info, options)
      end
    else
      {:error, :email_not_verified} ->
        {:error, EmailNotVerified.exception(strategy: strategy.name)}

      {:error, %InvalidToken{reason: reason}} ->
        Logger.debug("Firebase token rejected",
          reason: reason,
          strategy: strategy.name
        )

        :telemetry.execute(
          [:ash_authentication_firebase, :strategy, :token_rejected],
          %{count: 1},
          %{reason: reason, strategy: strategy.name}
        )

        {:error, Errors.InvalidToken.exception(type: :sign_in)}

      _ ->
        {:error, Errors.InvalidToken.exception(type: :sign_in)}
    end
  end

  defp do_register(strategy, user_info, options) do
    action = Resource.Info.action(strategy.resource, strategy.register_action_name, :create)

    strategy.resource
    |> Changeset.new()
    |> Changeset.set_context(%{
      private: %{
        ash_authentication?: true
      }
    })
    |> Changeset.for_create(
      strategy.register_action_name,
      %{user_info: user_info},
      upsert?: true,
      upsert_identity: action.upsert_identity
    )
    |> Ash.create(options)
  end

  defp do_sign_in(strategy, user_info, options) do
    strategy.resource
    |> Query.new()
    |> Query.set_context(%{
      private: %{
        ash_authentication?: true
      }
    })
    |> Query.for_read(strategy.sign_in_action_name, %{user_info: user_info})
    |> Ash.read(options)
    |> case do
      {:ok, [user]} ->
        {:ok, user}

      {:ok, []} ->
        {:error,
         AuthenticationFailed.exception(
           strategy: strategy,
           caused_by: %{
             module: __MODULE__,
             strategy: strategy,
             action: :sign_in,
             message: "Query returned no users"
           }
         )}

      {:ok, _users} ->
        {:error,
         AuthenticationFailed.exception(
           strategy: strategy,
           caused_by: %{
             module: __MODULE__,
             strategy: strategy,
             action: :sign_in,
             message: "Query returned too many users"
           }
         )}

      {:error, %AuthenticationFailed{} = error} ->
        {:error, error}

      {:error, error} when is_exception(error) ->
        {:error,
         AuthenticationFailed.exception(
           strategy: strategy,
           caused_by: error
         )}

      {:error, other} ->
        {:error,
         AuthenticationFailed.exception(
           strategy: strategy,
           caused_by: %{
             module: __MODULE__,
             strategy: strategy,
             action: :sign_in,
             reason: other
           }
         )}
    end
  end

  defp check_email_verified(strategy, fields) do
    if strategy.require_email_verified? and email_unverified?(fields) do
      {:error, :email_not_verified}
    else
      :ok
    end
  end

  defp email_unverified?(fields) do
    is_binary(fields["email"]) and fields["email"] != "" and
      fields["email_verified"] != true
  end

  defp verify_firebase_token(token, project_id) do
    TokenVerifier.verify(token, project_id)
  end

  defp get_firebase_token_from_params(params, token_input) do
    case Map.get(params, token_input) || Map.get(params, Atom.to_string(token_input)) do
      token when is_binary(token) and token != "" -> {:ok, token}
      _ -> {:error, :missing_token}
    end
  end

  defp fetch_secret(strategy, secret_name, context) do
    path = [:authentication, :strategies, strategy.name, secret_name]

    with {:ok, {secret_module, secret_opts}} <- Map.fetch(strategy, secret_name),
         {:ok, secret} when is_binary(secret) and byte_size(secret) > 0 <-
           AshAuthentication.Secret.secret_for(
             secret_module,
             path,
             strategy.resource,
             secret_opts,
             context
           ) do
      {:ok, secret}
    else
      {:ok, secret} when is_binary(secret) and byte_size(secret) > 0 ->
        {:ok, secret}

      _ ->
        {:error, Errors.MissingSecret.exception(path: path, resource: strategy.resource)}
    end
  end

  defp build_user_info(fields, uid) do
    fields
    |> Map.put("uid", uid)
  end
end
