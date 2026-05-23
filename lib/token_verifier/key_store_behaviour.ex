defmodule AshAuthentication.Firebase.TokenVerifier.KeyStoreBehaviour do
  @moduledoc """
  Behaviour for modules that supply Firebase public keys to the token verifier.
  """

  @callback get_keys() ::
              {:ok, %{optional(String.t()) => JOSE.JWK.t()}} | {:error, term()}
end
