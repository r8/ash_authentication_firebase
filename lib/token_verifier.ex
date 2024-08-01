defmodule AshAuthentication.Firebase.TokenVerifier do
  @moduledoc """
  Verifies Firebase ID tokens using Google's public keys.
  Implements all security checks as per Firebase Auth documentation.
  """

  require Logger
  alias AshAuthentication.Firebase.TokenVerifier.KeyStore

  @issuer_prefix "https://securetoken.google.com/"

  @type verification_error ::
          :invalid_token
          | :expired_token
          | :invalid_signature
          | :invalid_issuer
          | :invalid_audience
          | :token_not_yet_valid
          | :missing_key_id
          | :key_not_found
          | {:unexpected_error, any()}

  @type verification_result ::
          {:ok, String.t(), map()} | {:error, verification_error()}

  @doc """
  Verifies a Firebase ID token.
  Returns {:ok, token, claims} if the token is valid,
  {:error, reason} otherwise.
  """
  @spec verify(String.t(), String.t()) :: verification_result()
  def verify(token, project_id) when is_binary(token) and is_binary(project_id) do
    with {:ok, decoded_token} <- decode_token_segments(token),
         {:ok, key_id} <- get_key_id(decoded_token),
         {:ok, keys} <- KeyStore.get_keys(),
         {:ok, public_key} <- get_public_key(keys, key_id),
         {:ok, claims} <- verify_token(token, public_key, project_id) do
      {:ok, token, claims}
    else
      {:error, reason} = error ->
        Logger.debug("Token verification failed: #{inspect(reason)}")
        error
    end
  end

  def verify(nil, _project_id), do: {:error, :invalid_token}
  def verify(_token, nil), do: {:error, :invalid_token}

  defp decode_token_segments(token) do
    case String.split(token, ".") do
      [_header, _payload, _signature] = segments ->
        decode_jwt_segments(segments)

      _ ->
        {:error, :invalid_token}
    end
  end

  defp decode_jwt_segments([header, payload, signature]) do
    with {:ok, decoded_header} <- base64_decode_segment(header),
         {:ok, header_claims} <- Jason.decode(decoded_header),
         {:ok, decoded_payload} <- base64_decode_segment(payload),
         {:ok, payload_claims} <- Jason.decode(decoded_payload) do
      {:ok,
       %{
         header: header_claims,
         payload: payload_claims,
         signature: signature
       }}
    else
      _ -> {:error, :invalid_token}
    end
  end

  defp base64_decode_segment(segment) do
    segment
    |> String.replace("-", "+")
    |> String.replace("_", "/")
    |> pad_base64()
    |> Base.decode64(padding: false)
  end

  defp pad_base64(str) do
    case rem(String.length(str), 4) do
      2 -> str <> "=="
      3 -> str <> "="
      _ -> str
    end
  end

  defp get_key_id(%{header: %{"kid" => kid}}) when is_binary(kid), do: {:ok, kid}
  defp get_key_id(_), do: {:error, :missing_key_id}

  defp get_public_key(keys, key_id) do
    case Map.get(keys, key_id) do
      nil ->
        {:error, :key_not_found}

      cert_string ->
        cert_string
        |> :public_key.pem_decode()
        |> List.first()
        |> :public_key.pem_entry_decode()
        |> then(&{:ok, &1})
    end
  end

  defp verify_token(token, public_key, project_id) do
    signer = Joken.Signer.create("RS256", %{"pem" => public_key})
    expected_claims = generate_validation_claims(project_id)

    case Joken.verify(token, signer, expected_claims) do
      {:ok, claims} ->
        verify_time_claims(claims)

      {:error, reason} when reason in [:signature_error, :invalid_signature] ->
        {:error, :invalid_signature}

      {:error, [:validation, reason | _]} ->
        translate_validation_error(reason)

      {:error, _} ->
        {:error, :invalid_token}
    end
  end

  defp generate_validation_claims(project_id) do
    %{
      "iss" => @issuer_prefix <> project_id,
      "aud" => project_id
    }
  end

  defp verify_time_claims(claims) do
    now = DateTime.utc_now() |> DateTime.to_unix()

    cond do
      claims["exp"] < now ->
        {:error, :expired_token}

      claims["iat"] > now ->
        {:error, :token_not_yet_valid}

      true ->
        {:ok, claims}
    end
  end

  defp translate_validation_error({"iss", _}), do: {:error, :invalid_issuer}
  defp translate_validation_error({"aud", _}), do: {:error, :invalid_audience}
  defp translate_validation_error(_), do: {:error, :invalid_token}
end
