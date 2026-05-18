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

  def verify(token, project_id) when is_binary(token) and is_binary(project_id) do
    issuer = @issuer_prefix <> project_id

    with {:jwt_header, %{fields: %{"kid" => kid, "alg" => @algorithm}}} <- peek_token_kid(token),
         # read key from store
         {:ok, keys} = KeyStore.get_keys(),
         {:ok, %JOSE.JWK{} = key} <- get_public_key(keys, kid),
         # check if verify returns true and issuer matches
         {:verify, {true, %{fields: %{"iss" => ^issuer, "sub" => sub, "exp" => exp}} = data, _}} <-
           {:verify, JOSE.JWT.verify_strict(key, [@algorithm], token)},
         # Verify exp date
         {:verify, {:ok, _}} <- {:verify, verify_expiry(exp)},
         %{fields: fields} <- data do
      {:ok, sub, fields}
    else
      :invalid_jwt ->
        {:error, "Invalid JWT"}

      {:jwt_header, _} ->
        {:error, "Invalid JWT header, `kid` or `alg` missing/incorrect"}

      {:key, _} ->
        {:error, "Public key retrieved from google was not found or could not be parsed"}

      {:verify, {false, _, _}} ->
        {:error, "Invalid signature"}

      {:verify, {true, _, _}} ->
        {:error, "Signed by invalid issuer"}

      {:verify, {:expired, _}} ->
        {:error, "Expired JWT"}

      {:verify, _} ->
        {:error, "None of public keys matched auth token's key ids"}
    end
  end

  def verify(nil, _project_id), do: {:error, :invalid_token}
  def verify(_token, nil), do: {:error, :invalid_project_id}

  defp get_public_key(keys, key_id) do
    case Map.get(keys, key_id) do
      nil ->
        {:error, :key_not_found}

      cert_string ->
        {:ok, cert_string}
    end
  end

  defp peek_token_kid(token_string) do
    {:jwt_header, JOSE.JWT.peek_protected(token_string)}
  rescue
    _ -> :invalid_jwt
  end

  defp verify_expiry(exp) do
    if exp > DateTime.utc_now() |> DateTime.to_unix() do
      {:ok, exp}
    else
      {:expired, exp}
    end
  end
end
