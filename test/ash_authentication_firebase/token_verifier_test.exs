defmodule AshAuthentication.Firebase.TokenVerifierTest do
  use ExUnit.Case, async: true

  import Mox

  alias AshAuthentication.Firebase.Errors.InvalidToken
  alias AshAuthentication.Firebase.TokenVerifier
  alias AshAuthentication.Firebase.TokenVerifier.KeyStoreMock

  @project_id "test-project"
  @kid "test-kid"
  @other_kid "other-kid"

  setup_all do
    private_jwk = JOSE.JWK.generate_key({:rsa, 2048})
    public_jwk = JOSE.JWK.to_public(private_jwk)
    other_private_jwk = JOSE.JWK.generate_key({:rsa, 2048})

    %{
      private_jwk: private_jwk,
      public_jwk: public_jwk,
      other_private_jwk: other_private_jwk
    }
  end

  setup :verify_on_exit!

  setup %{public_jwk: public_jwk} do
    stub(KeyStoreMock, :get_keys, fn -> {:ok, %{@kid => public_jwk}} end)
    stub(KeyStoreMock, :refresh_now, fn -> :ok end)
    :ok
  end

  describe "verify/2" do
    test "returns :invalid_token when token is nil" do
      assert {:error, %InvalidToken{reason: :invalid_token}} =
               TokenVerifier.verify(nil, @project_id)
    end

    test "returns :invalid_project_id when project_id is nil" do
      assert {:error, %InvalidToken{reason: :invalid_project_id}} =
               TokenVerifier.verify("token", nil)
    end

    test "returns :invalid_project_id when project_id is non-binary" do
      assert {:error, %InvalidToken{reason: :invalid_project_id}} =
               TokenVerifier.verify("token", 123)
    end

    test "returns :invalid_project_id when project_id is an empty string" do
      assert {:error, %InvalidToken{reason: :invalid_project_id}} =
               TokenVerifier.verify("token", "")
    end

    test "returns :invalid_token when token is non-binary" do
      assert {:error, %InvalidToken{reason: :invalid_token}} =
               TokenVerifier.verify(123, @project_id)
    end

    test "returns :invalid_token when token is an empty string" do
      assert {:error, %InvalidToken{reason: :invalid_token}} =
               TokenVerifier.verify("", @project_id)
    end

    test "returns :invalid_header for non-JWT garbage" do
      assert {:error, %InvalidToken{reason: :invalid_header}} =
               TokenVerifier.verify("not-a-jwt", @project_id)
    end

    test "returns :invalid_header when alg is not RS256", %{private_jwk: jwk} do
      # JOSE rejects RSA keys with HS256, so sign with an HMAC oct key
      hmac_jwk = JOSE.JWK.from_oct(:crypto.strong_rand_bytes(32))
      token = sign(valid_claims(), %{"alg" => "HS256", "kid" => @kid}, hmac_jwk)

      assert {:error, %InvalidToken{reason: :invalid_header}} =
               TokenVerifier.verify(token, @project_id)

      _ = jwk
    end

    test "returns :invalid_header when kid is missing", %{private_jwk: jwk} do
      token = sign(valid_claims(), %{"alg" => "RS256"}, jwk)

      assert {:error, %InvalidToken{reason: :invalid_header}} =
               TokenVerifier.verify(token, @project_id)
    end

    test "returns :key_not_found when kid does not match any known key",
         %{private_jwk: jwk} do
      token = sign(valid_claims(), %{"alg" => "RS256", "kid" => @other_kid}, jwk)

      assert {:error, %InvalidToken{reason: :key_not_found}} =
               TokenVerifier.verify(token, @project_id)
    end

    test "returns :invalid_signature when signed by a different key",
         %{other_private_jwk: jwk} do
      token = sign(valid_claims(), %{"alg" => "RS256", "kid" => @kid}, jwk)

      assert {:error, %InvalidToken{reason: :invalid_signature}} =
               TokenVerifier.verify(token, @project_id)
    end

    test "returns :invalid_issuer when iss is wrong", %{private_jwk: jwk} do
      token =
        valid_claims(%{"iss" => "https://securetoken.google.com/other-project"})
        |> sign(%{"alg" => "RS256", "kid" => @kid}, jwk)

      assert {:error, %InvalidToken{reason: :invalid_issuer}} =
               TokenVerifier.verify(token, @project_id)
    end

    test "returns :invalid_audience when aud is wrong", %{private_jwk: jwk} do
      token =
        valid_claims(%{"aud" => "other-project"})
        |> sign(%{"alg" => "RS256", "kid" => @kid}, jwk)

      assert {:error, %InvalidToken{reason: :invalid_audience}} =
               TokenVerifier.verify(token, @project_id)
    end

    test "returns :invalid_sub when sub is missing", %{private_jwk: jwk} do
      claims = valid_claims() |> Map.delete("sub")
      token = sign(claims, %{"alg" => "RS256", "kid" => @kid}, jwk)

      assert {:error, %InvalidToken{reason: :invalid_sub}} =
               TokenVerifier.verify(token, @project_id)
    end

    test "returns :invalid_sub when sub is an empty string", %{private_jwk: jwk} do
      token =
        valid_claims(%{"sub" => ""})
        |> sign(%{"alg" => "RS256", "kid" => @kid}, jwk)

      assert {:error, %InvalidToken{reason: :invalid_sub}} =
               TokenVerifier.verify(token, @project_id)
    end

    test "returns :invalid_sub when sub is not a binary", %{private_jwk: jwk} do
      token =
        valid_claims(%{"sub" => 12_345})
        |> sign(%{"alg" => "RS256", "kid" => @kid}, jwk)

      assert {:error, %InvalidToken{reason: :invalid_sub}} =
               TokenVerifier.verify(token, @project_id)
    end

    test "returns :expired when exp is in the past", %{private_jwk: jwk} do
      now = System.os_time(:second)

      token =
        valid_claims(%{"exp" => now - 60})
        |> sign(%{"alg" => "RS256", "kid" => @kid}, jwk)

      assert {:error, %InvalidToken{reason: :expired}} = TokenVerifier.verify(token, @project_id)
    end

    test "returns :expired when exp is missing", %{private_jwk: jwk} do
      claims = valid_claims() |> Map.delete("exp")
      token = sign(claims, %{"alg" => "RS256", "kid" => @kid}, jwk)
      assert {:error, %InvalidToken{reason: :expired}} = TokenVerifier.verify(token, @project_id)
    end

    test "returns :invalid_iat when iat is in the future", %{private_jwk: jwk} do
      now = System.os_time(:second)

      token =
        valid_claims(%{"iat" => now + 600})
        |> sign(%{"alg" => "RS256", "kid" => @kid}, jwk)

      assert {:error, %InvalidToken{reason: :invalid_iat}} =
               TokenVerifier.verify(token, @project_id)
    end

    test "returns :invalid_iat when iat is missing", %{private_jwk: jwk} do
      claims = valid_claims() |> Map.delete("iat")
      token = sign(claims, %{"alg" => "RS256", "kid" => @kid}, jwk)

      assert {:error, %InvalidToken{reason: :invalid_iat}} =
               TokenVerifier.verify(token, @project_id)
    end

    test "returns :invalid_auth_time when auth_time is in the future",
         %{private_jwk: jwk} do
      now = System.os_time(:second)

      token =
        valid_claims(%{"auth_time" => now + 600})
        |> sign(%{"alg" => "RS256", "kid" => @kid}, jwk)

      assert {:error, %InvalidToken{reason: :invalid_auth_time}} =
               TokenVerifier.verify(token, @project_id)
    end

    test "returns :invalid_auth_time when auth_time is missing", %{private_jwk: jwk} do
      claims = valid_claims() |> Map.delete("auth_time")
      token = sign(claims, %{"alg" => "RS256", "kid" => @kid}, jwk)

      assert {:error, %InvalidToken{reason: :invalid_auth_time}} =
               TokenVerifier.verify(token, @project_id)
    end

    test "returns {:ok, sub, claims} for a fully valid token", %{private_jwk: jwk} do
      claims = valid_claims()
      token = sign(claims, %{"alg" => "RS256", "kid" => @kid}, jwk)

      assert {:ok, "user-123", returned_claims} = TokenVerifier.verify(token, @project_id)
      assert returned_claims["sub"] == "user-123"
      assert returned_claims["iss"] == "https://securetoken.google.com/#{@project_id}"
      assert returned_claims["aud"] == @project_id
      assert returned_claims["exp"] == claims["exp"]
      assert returned_claims["iat"] == claims["iat"]
      assert returned_claims["auth_time"] == claims["auth_time"]
    end

    test "propagates :key_not_found when KeyStore returns no matching key",
         %{private_jwk: jwk} do
      # get_keys is called twice: initial miss + retry after refresh_now
      expect(KeyStoreMock, :get_keys, 2, fn -> {:ok, %{}} end)
      expect(KeyStoreMock, :refresh_now, fn -> :ok end)
      token = sign(valid_claims(), %{"alg" => "RS256", "kid" => @kid}, jwk)

      assert {:error, %InvalidToken{reason: :key_not_found}} =
               TokenVerifier.verify(token, @project_id)
    end

    test "the returned InvalidToken struct renders its reason in the exception message" do
      assert {:error, %InvalidToken{} = error} = TokenVerifier.verify(nil, "p")
      assert Exception.message(error) == "Firebase token verification failed: invalid_token"
    end
  end

  describe "clock skew leeway" do
    setup do
      previous = Application.get_env(:ash_authentication_firebase, :clock_skew_leeway_seconds)

      on_exit(fn ->
        case previous do
          nil -> Application.delete_env(:ash_authentication_firebase, :clock_skew_leeway_seconds)
          v -> Application.put_env(:ash_authentication_firebase, :clock_skew_leeway_seconds, v)
        end
      end)

      :ok
    end

    test "accepts a token whose iat is slightly in the future within the default leeway",
         %{private_jwk: jwk} do
      now = System.os_time(:second)

      token =
        valid_claims(%{"iat" => now + 30})
        |> sign(%{"alg" => "RS256", "kid" => @kid}, jwk)

      assert {:ok, "user-123", _claims} = TokenVerifier.verify(token, @project_id)
    end

    test "rejects the same token when leeway is configured to zero",
         %{private_jwk: jwk} do
      Application.put_env(:ash_authentication_firebase, :clock_skew_leeway_seconds, 0)
      now = System.os_time(:second)

      token =
        valid_claims(%{"iat" => now + 30})
        |> sign(%{"alg" => "RS256", "kid" => @kid}, jwk)

      assert {:error, %InvalidToken{reason: :invalid_iat}} =
               TokenVerifier.verify(token, @project_id)
    end

    test "accepts a token that just expired within the default leeway",
         %{private_jwk: jwk} do
      now = System.os_time(:second)

      token =
        valid_claims(%{"exp" => now - 30})
        |> sign(%{"alg" => "RS256", "kid" => @kid}, jwk)

      assert {:ok, "user-123", _claims} = TokenVerifier.verify(token, @project_id)
    end
  end

  describe "key store not initialized" do
    test "refreshes and recovers when get_keys returns :not_initialized first",
         %{private_jwk: jwk, public_jwk: public_jwk} do
      {:ok, agent} = Agent.start_link(fn -> 0 end)

      expect(KeyStoreMock, :get_keys, 2, fn ->
        case Agent.get_and_update(agent, &{&1, &1 + 1}) do
          0 -> {:error, :not_initialized}
          _ -> {:ok, %{@kid => public_jwk}}
        end
      end)

      expect(KeyStoreMock, :refresh_now, fn -> :ok end)

      token = sign(valid_claims(), %{"alg" => "RS256", "kid" => @kid}, jwk)

      assert {:ok, "user-123", _claims} = TokenVerifier.verify(token, @project_id)
    end

    test "returns :key_not_found when refresh fails and key remains uninitialized",
         %{private_jwk: jwk} do
      expect(KeyStoreMock, :get_keys, 2, fn -> {:error, :not_initialized} end)
      expect(KeyStoreMock, :refresh_now, fn -> {:error, :timeout} end)

      token = sign(valid_claims(), %{"alg" => "RS256", "kid" => @kid}, jwk)

      assert {:error, %InvalidToken{reason: :key_not_found}} =
               TokenVerifier.verify(token, @project_id)
    end
  end

  describe "malformed payload" do
    test "returns :malformed_payload when verify_strict raises", %{private_jwk: jwk} do
      valid = sign(valid_claims(), %{"alg" => "RS256", "kid" => @kid}, jwk)
      [header, _payload, sig] = String.split(valid, ".")
      mangled = Enum.join([header, "!!!not-base64!!!", sig], ".")

      assert {:error, %InvalidToken{reason: :malformed_payload}} =
               TokenVerifier.verify(mangled, @project_id)
    end
  end

  describe "unknown kid" do
    test "synchronously refreshes the key store and recovers a valid token",
         %{private_jwk: jwk, public_jwk: public_jwk} do
      {:ok, agent} = Agent.start_link(fn -> 0 end)

      expect(KeyStoreMock, :get_keys, 2, fn ->
        case Agent.get_and_update(agent, &{&1, &1 + 1}) do
          0 -> {:ok, %{}}
          _ -> {:ok, %{@kid => public_jwk}}
        end
      end)

      expect(KeyStoreMock, :refresh_now, fn -> :ok end)

      token = sign(valid_claims(), %{"alg" => "RS256", "kid" => @kid}, jwk)

      assert {:ok, "user-123", _claims} = TokenVerifier.verify(token, @project_id)
    end

    test "returns :key_not_found when the refresh does not add the missing kid",
         %{private_jwk: jwk} do
      expect(KeyStoreMock, :get_keys, 2, fn -> {:ok, %{}} end)
      expect(KeyStoreMock, :refresh_now, fn -> :ok end)

      token = sign(valid_claims(), %{"alg" => "RS256", "kid" => @kid}, jwk)

      assert {:error, %InvalidToken{reason: :key_not_found}} =
               TokenVerifier.verify(token, @project_id)
    end

    test "returns :key_not_found when the refresh itself fails", %{private_jwk: jwk} do
      expect(KeyStoreMock, :get_keys, 2, fn -> {:ok, %{}} end)
      expect(KeyStoreMock, :refresh_now, fn -> {:error, :timeout} end)

      token = sign(valid_claims(), %{"alg" => "RS256", "kid" => @kid}, jwk)

      assert {:error, %InvalidToken{reason: :key_not_found}} =
               TokenVerifier.verify(token, @project_id)
    end
  end

  defp valid_claims(overrides \\ %{}) do
    now = System.os_time(:second)

    Map.merge(
      %{
        "iss" => "https://securetoken.google.com/#{@project_id}",
        "aud" => @project_id,
        "sub" => "user-123",
        "exp" => now + 3600,
        "iat" => now - 10,
        "auth_time" => now - 20
      },
      overrides
    )
  end

  defp sign(claims, jws_header, jwk) do
    {_, token} = JOSE.JWS.compact(JOSE.JWT.sign(jwk, jws_header, claims))
    token
  end
end
