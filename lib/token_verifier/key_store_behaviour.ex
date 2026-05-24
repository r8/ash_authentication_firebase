defmodule AshAuthentication.Firebase.TokenVerifier.KeyStoreBehaviour do
  @moduledoc """
  Behaviour for modules that supply Firebase public keys to the token verifier.
  """

  @doc """
  Returns the currently cached Firebase public keys, keyed by `kid`.

  Implementations must not block — this is called on the hot path of every
  token verification. Before the first successful fetch completes the call
  may return `{:error, :not_initialized}`; the token verifier interprets that
  as a cache miss and falls back to `c:refresh_now/0`.
  """
  @callback get_keys() ::
              {:ok, %{optional(String.t()) => JOSE.JWK.t()}} | {:error, term()}

  @doc """
  Forces a synchronous refresh of the cached keys.

  Used by the token verifier on a `kid` miss to recover from Google key
  rotation between scheduled refreshes. The call blocks until the fetch
  finishes (or times out) and is expected to be debounced inside the
  implementation so that repeated cache misses cannot hammer Google.
  """
  @callback refresh_now() :: :ok | {:error, term()}
end
