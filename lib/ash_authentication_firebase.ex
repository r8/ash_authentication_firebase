defmodule AshAuthentication.Firebase do
  @moduledoc """
  Firebase token authentication strategy for AshAuthentication.
  """

  use Application

  @finch_name __MODULE__.Finch

  @impl Application
  @spec start(Application.start_type(), term()) :: {:ok, pid()} | {:error, term()}
  def start(_type, _args) do
    children =
      case Application.get_env(
             :ash_authentication_firebase,
             :key_store,
             AshAuthentication.Firebase.TokenVerifier.KeyStore
           ) do
        AshAuthentication.Firebase.TokenVerifier.KeyStore ->
          [
            {Finch, name: @finch_name},
            {AshAuthentication.Firebase.TokenVerifier.KeyStore,
             name: AshAuthentication.Firebase.TokenVerifier.KeyStore}
          ]

        _ ->
          []
      end

    opts = [strategy: :one_for_one, name: AshAuthentication.Firebase.Supervisor]
    Supervisor.start_link(children, opts)
  end
end
