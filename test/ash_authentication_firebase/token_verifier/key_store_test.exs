defmodule AshAuthentication.Firebase.TokenVerifier.KeyStoreTest do
  use ExUnit.Case, async: true

  alias AshAuthentication.Firebase.TokenVerifier.KeyStore

  describe "convert_to_jose_keys/1" do
    setup do
      jwk = JOSE.JWK.generate_key({:rsa, 2048})
      {%{kty: kty}, public_map} = jwk |> JOSE.JWK.to_public() |> JOSE.JWK.to_map()
      {_, pem} = jwk |> JOSE.JWK.to_public() |> JOSE.JWK.to_pem()
      %{pem: pem, kty: kty, public_map: public_map}
    end

    test "returns {:ok, %{kid => jwk}} for a map of valid PEM strings", %{pem: pem} do
      assert {:ok, keys} = KeyStore.convert_to_jose_keys(%{"kid-1" => pem, "kid-2" => pem})
      assert map_size(keys) == 2
      assert %JOSE.JWK{} = keys["kid-1"]
      assert %JOSE.JWK{} = keys["kid-2"]
    end

    test "skips non-binary values without crashing", %{pem: pem} do
      assert {:ok, keys} = KeyStore.convert_to_jose_keys(%{"kid-1" => pem, "kid-2" => 12_345})
      assert Map.keys(keys) == ["kid-1"]
    end

    test "skips garbage string values without crashing", %{pem: pem} do
      assert {:ok, keys} =
               KeyStore.convert_to_jose_keys(%{"kid-1" => pem, "kid-2" => "not a PEM"})

      assert Map.keys(keys) == ["kid-1"]
    end

    test "skips empty string values", %{pem: pem} do
      assert {:ok, keys} = KeyStore.convert_to_jose_keys(%{"kid-1" => pem, "kid-2" => ""})
      assert Map.keys(keys) == ["kid-1"]
    end

    test "skips nil values", %{pem: pem} do
      assert {:ok, keys} = KeyStore.convert_to_jose_keys(%{"kid-1" => pem, "kid-2" => nil})
      assert Map.keys(keys) == ["kid-1"]
    end

    test "returns :no_valid_keys when every value is garbage" do
      assert {:error, :no_valid_keys} =
               KeyStore.convert_to_jose_keys(%{"kid-1" => "junk", "kid-2" => 123, "kid-3" => nil})
    end

    test "returns :no_valid_keys for an empty map" do
      assert {:error, :no_valid_keys} = KeyStore.convert_to_jose_keys(%{})
    end

    test "returns :invalid_key_response for non-map input" do
      assert {:error, :invalid_key_response} = KeyStore.convert_to_jose_keys("not a map")
      assert {:error, :invalid_key_response} = KeyStore.convert_to_jose_keys(nil)
      assert {:error, :invalid_key_response} = KeyStore.convert_to_jose_keys([])
    end

    test "skips entries whose key is not a binary", %{pem: pem} do
      assert {:ok, keys} = KeyStore.convert_to_jose_keys(%{"kid-1" => pem, 42 => pem})
      assert Map.keys(keys) == ["kid-1"]
    end
  end
end
