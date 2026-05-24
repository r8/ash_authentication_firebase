defmodule AshAuthentication.Firebase.TokenVerifier do
  @moduledoc """
  Verifies Firebase ID tokens using Google's public keys.
  Implements all security checks as per Firebase Auth documentation.

  ## Clock skew

  Time-based claims (`exp`, `iat`, `auth_time`) are evaluated with a small
  leeway to tolerate clock drift between Firebase / the client and the
  server. The default leeway is 60 seconds; override with:

      config :ash_authentication_firebase, clock_skew_leeway_seconds: 30

  Valid values are integers in `0..300`. Anything outside that range — or
  a non-integer — is logged as a warning and the default is used.
  """

  require Logger

  alias AshAuthentication.Firebase.Errors.InvalidToken

  @issuer_prefix "https://securetoken.google.com/"
  @default_clock_skew_leeway 60
  @max_clock_skew_leeway 300
  @clock_skew_cache_key {__MODULE__, :clock_skew_leeway}
  @max_sub_length 128

  @type claims :: %{optional(String.t()) => term()}

  @doc """
  Verifies a Firebase ID token against the provided project ID.

  On success returns `{:ok, sub, claims}` where `sub` is the Firebase user id.
  On failure returns `{:error, AshAuthentication.Firebase.Errors.InvalidToken.t()}`
  whose `:reason` field describes the specific failure (see
  `t:AshAuthentication.Firebase.Errors.InvalidToken.reason/0`).
  """
  @spec verify(term(), term()) ::
          {:ok, sub :: String.t(), claims()} | {:error, InvalidToken.t()}
  def verify(token, project_id)
      when is_binary(token) and is_binary(project_id) and token != "" and project_id != "" do
    issuer = @issuer_prefix <> project_id
    now = System.os_time(:second)
    leeway = clock_skew_leeway()

    with {:jwt_header, %JOSE.JWS{alg: {_, :RS256}, fields: %{"kid" => kid}}}
         when is_binary(kid) and kid != "" <-
           peek_token_kid(token),
         {:ok, %JOSE.JWK{} = key} <- get_public_key_or_refresh(kid),
         {:verify, {true, %{fields: fields}, _}} <- verify_jwt(key, token),
         {:validate_iss, true} <- {:validate_iss, fields["iss"] == issuer},
         {:validate_aud, true} <- {:validate_aud, fields["aud"] == project_id},
         {:validate_sub, true} <- {:validate_sub, valid_sub?(fields["sub"])},
         {:validate_exp, true} <-
           {:validate_exp, is_integer(fields["exp"]) and fields["exp"] > now - leeway},
         {:validate_iat, true} <-
           {:validate_iat, is_integer(fields["iat"]) and fields["iat"] <= now + leeway},
         {:validate_auth, true} <-
           {:validate_auth,
            is_integer(fields["auth_time"]) and fields["auth_time"] <= now + leeway} do
      {:ok, fields["sub"], fields}
    else
      {:jwt_header, _} -> error(:invalid_header)
      {:verify, {false, _, _}} -> error(:invalid_signature)
      {:verify, _} -> error(:malformed_payload)
      {:validate_iss, _} -> error(:invalid_issuer)
      {:validate_aud, _} -> error(:invalid_audience)
      {:validate_sub, _} -> error(:invalid_sub)
      {:validate_exp, _} -> error(:expired)
      {:validate_iat, _} -> error(:invalid_iat)
      {:validate_auth, _} -> error(:invalid_auth_time)
      {:error, _} -> error(:key_not_found)
    end
  end

  def verify(_token, project_id) when not is_binary(project_id) or project_id == "" do
    error(:invalid_project_id)
  end

  def verify(_token, _project_id), do: error(:invalid_token)

  defp error(reason), do: {:error, InvalidToken.exception(reason: reason)}

  defp valid_sub?(sub) when is_binary(sub),
    do: sub != "" and byte_size(sub) <= @max_sub_length

  defp valid_sub?(_), do: false

  defp get_public_key_or_refresh(kid) do
    case lookup_key(kid) do
      {:ok, jwk} ->
        {:ok, jwk}

      {:error, _} ->
        _ = key_store().refresh_now()

        case lookup_key(kid) do
          {:ok, jwk} -> {:ok, jwk}
          {:error, _} -> {:error, :key_not_found}
        end
    end
  end

  defp lookup_key(kid) do
    case key_store().get_keys() do
      {:ok, keys} ->
        case Map.fetch(keys, kid) do
          {:ok, jwk} -> {:ok, jwk}
          :error -> {:error, :key_not_found}
        end

      error ->
        error
    end
  end

  defp peek_token_kid(token_string) do
    {:jwt_header, JOSE.JWT.peek_protected(token_string)}
  rescue
    _ -> {:jwt_header, :invalid}
  end

  defp verify_jwt(key, token) do
    {:verify, JOSE.JWT.verify_strict(key, ["RS256"], token)}
  rescue
    _ -> {:verify, :malformed}
  end

  defp key_store do
    Application.get_env(
      :ash_authentication_firebase,
      :key_store,
      AshAuthentication.Firebase.TokenVerifier.KeyStore
    )
  end

  defp clock_skew_leeway do
    case :persistent_term.get(@clock_skew_cache_key, :__absent__) do
      :__absent__ ->
        value = resolve_clock_skew_leeway()
        :persistent_term.put(@clock_skew_cache_key, value)
        value

      cached ->
        cached
    end
  end

  defp resolve_clock_skew_leeway do
    case Application.get_env(
           :ash_authentication_firebase,
           :clock_skew_leeway_seconds,
           @default_clock_skew_leeway
         ) do
      n when is_integer(n) and n >= 0 and n <= @max_clock_skew_leeway ->
        n

      other ->
        Logger.warning(
          "Invalid :clock_skew_leeway_seconds #{inspect(other)} " <>
            "(must be an integer in 0..#{@max_clock_skew_leeway}); " <>
            "falling back to #{@default_clock_skew_leeway}s"
        )

        @default_clock_skew_leeway
    end
  end

  @doc false
  # For tests that change :clock_skew_leeway_seconds at runtime.
  def __reset_clock_skew_cache__ do
    :persistent_term.erase(@clock_skew_cache_key)
    :ok
  end
end
