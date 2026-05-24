defmodule AshAuthentication.Firebase.TokenVerifier do
  @moduledoc """
  Verifies Firebase ID tokens using Google's public keys.
  Implements all security checks as per Firebase Auth documentation.
  """

  alias AshAuthentication.Firebase.Errors.InvalidToken

  @issuer_prefix "https://securetoken.google.com/"

  @type claims :: %{optional(String.t()) => term()}

  @doc """
  Verifies a Firebase ID token against the provided project ID.

  On success returns `{:ok, sub, claims}` where `sub` is the Firebase user id.
  On failure returns `{:error, AshAuthentication.Firebase.Errors.InvalidToken.t()}`
  whose `:reason` field describes the specific failure (see
  `t:AshAuthentication.Firebase.Errors.InvalidToken.reason/0`).
  """
  @spec verify(String.t() | nil, String.t() | nil) ::
          {:ok, sub :: String.t(), claims()} | {:error, InvalidToken.t()}
  def verify(nil, _project_id), do: error(:invalid_token)
  def verify(_token, nil), do: error(:invalid_project_id)

  def verify(token, project_id) when is_binary(token) and is_binary(project_id) do
    issuer = @issuer_prefix <> project_id
    now = System.os_time(:second)

    with {:jwt_header, %JOSE.JWS{alg: {_, :RS256}, fields: %{"kid" => kid}}} <-
           peek_token_kid(token),
         # read key from store, with one sync refresh-on-miss to handle key rotation
         {:ok, %JOSE.JWK{} = key} <- get_public_key_or_refresh(kid),
         # check if verify returns true
         {:verify, {true, %{fields: fields}, _}} <-
           {:verify, JOSE.JWT.verify_strict(key, ["RS256"], token)},
         {:validate_iss, true} <- {:validate_iss, fields["iss"] == issuer},
         {:validate_aud, true} <- {:validate_aud, fields["aud"] == project_id},
         {:validate_sub, true} <-
           {:validate_sub, is_binary(fields["sub"]) and fields["sub"] != ""},
         {:validate_exp, true} <-
           {:validate_exp, is_integer(fields["exp"]) and fields["exp"] > now},
         {:validate_iat, true} <-
           {:validate_iat, is_integer(fields["iat"]) and fields["iat"] <= now},
         {:validate_auth, true} <-
           {:validate_auth, is_integer(fields["auth_time"]) and fields["auth_time"] <= now} do
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
      {:error, :key_not_found} -> error(:key_not_found)
    end
  end

  defp error(reason), do: {:error, InvalidToken.exception(reason: reason)}

  defp get_public_key_or_refresh(kid) do
    case lookup_key(kid) do
      {:ok, jwk} ->
        {:ok, jwk}

      {:error, :key_not_found} ->
        _ = key_store().refresh_now()
        lookup_key(kid)

      other ->
        other
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

  defp key_store do
    Application.get_env(
      :ash_authentication_firebase,
      :key_store,
      AshAuthentication.Firebase.TokenVerifier.KeyStore
    )
  end
end
