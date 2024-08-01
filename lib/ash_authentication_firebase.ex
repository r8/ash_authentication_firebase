defmodule AshAuthentication.Firebase do
  @moduledoc """
  Firebase token authentication strategy for AshAuthentication.
  """

  use Application

  def start(_type, _args) do
    children = [
      {Finch, name: AshAuthentication.Firebase.Finch},
      {AshAuthentication.Firebase.TokenVerifier.KeyStore,
       name: AshAuthentication.Firebase.TokenVerifier.KeyStore}
    ]

    opts = [strategy: :one_for_one, name: AshAuthentication.Firebase.Supervisor]
    Supervisor.start_link(children, opts)
  end
end
