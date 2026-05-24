defmodule AshAuthentication.Firebase do
  @moduledoc """
  Firebase token authentication strategy for AshAuthentication.
  """

  use Application

  @default_finch_name __MODULE__.Finch

  @doc """
  Returns the Finch pool name used for HTTP requests.

  Defaults to the library-managed pool. Override with
  `config :ash_authentication_firebase, finch_name: MyApp.Finch` to share an
  externally-managed pool.
  """
  @spec finch_name() :: atom()
  def finch_name do
    Application.get_env(:ash_authentication_firebase, :finch_name, @default_finch_name)
  end

  @impl Application
  @spec start(Application.start_type(), term()) :: {:ok, pid()} | {:error, term()}
  def start(_type, _args) do
    finch_children =
      case Application.get_env(:ash_authentication_firebase, :finch_name) do
        nil -> [{Finch, name: @default_finch_name}]
        _ -> []
      end

    children =
      finch_children ++
        [
          {AshAuthentication.Firebase.TokenVerifier.KeyStore,
           name: AshAuthentication.Firebase.TokenVerifier.KeyStore}
        ]

    opts = [strategy: :one_for_one, name: AshAuthentication.Firebase.Supervisor]
    Supervisor.start_link(children, opts)
  end
end
