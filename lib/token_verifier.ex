defmodule AshAuthentication.Firebase.TokenVerifier do
  @moduledoc """
  Verifies Firebase ID tokens using Google's public keys.
  Implements all security checks as per Firebase Auth documentation.
  """

  require Logger
  alias AshAuthentication.Firebase.TokenVerifier.KeyStore

  @issuer_prefix "https://securetoken.google.com/"
  # Firebase Id tokens are always signed with RS256 algorithm
  @algorithm "RS256"

  @type claims :: %{optional(String.t()) => term()}
  @type error_reason ::
          :invalid_token
          | :invalid_project_id
          | :invalid_header
          | :key_not_found
          | :invalid_signature
          | :malformed_payload
          | :invalid_issuer
          | :invalid_audience
          | :expired
          | :invalid_iat
          | :invalid_auth_time

  @spec verify(String.t() | nil, String.t() | nil) ::
          {:ok, sub :: String.t(), claims()} | {:error, error_reason()}

  def verify(nil, _project_id), do: {:error, :invalid_token}
  def verify(_token, nil), do: {:error, :invalid_project_id}

  def verify(token, project_id) when is_binary(token) and is_binary(project_id) do
    issuer = @issuer_prefix <> project_id
    now = System.os_time(:second)

    with {:jwt_header, %{fields: %{"kid" => kid, "alg" => @algorithm}}} <- peek_token_kid(token),
         # read key from store
         {:ok, keys} <- KeyStore.get_keys(),
         {:ok, %JOSE.JWK{} = key} <- get_public_key(keys, kid),
         # check if verify returns true
         {:verify, {true, %{fields: fields}, _}} <-
           {:verify, JOSE.JWT.verify_strict(key, [@algorithm], token)},
         {:validate_iss, true} <- {:validate_iss, fields["iss"] == issuer},
         {:validate_aud, true} <- {:validate_aud, fields["aud"] == project_id},
         {:validate_exp, true} <-
           {:validate_exp, is_integer(fields["exp"]) and fields["exp"] > now},
         {:validate_iat, true} <-
           {:validate_iat, is_integer(fields["iat"]) and fields["iat"] <= now},
         {:validate_auth, true} <-
           {:validate_auth, is_integer(fields["auth_time"]) and fields["auth_time"] <= now} do
      {:ok, fields["sub"], fields}
    else
      {:jwt_header, _} -> {:error, :invalid_header}
      {:verify, {false, _, _}} -> {:error, :invalid_signature}
      {:verify, _} -> {:error, :malformed_payload}
      {:validate_iss, _} -> {:error, :invalid_issuer}
      {:validate_aud, _} -> {:error, :invalid_audience}
      {:validate_exp, _} -> {:error, :expired}
      {:validate_iat, _} -> {:error, :invalid_iat}
      {:validate_auth, _} -> {:error, :invalid_auth_time}
      error -> error
    end
  end

  defp get_public_key(keys, key_id) do
    case Map.get(keys, key_id) do
      nil -> {:error, :key_not_found}
      jwk -> {:ok, jwk}
    end
  end

  defp peek_token_kid(token_string) do
    {:jwt_header, JOSE.JWT.peek_protected(token_string)}
  rescue
    _ -> {:jwt_header, :invalid}
  end
end
