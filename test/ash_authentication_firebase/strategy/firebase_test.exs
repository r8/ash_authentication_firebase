defmodule AshAuthentication.Strategy.FirebaseTest do
  use ExUnit.Case, async: false

  import Mox

  alias AshAuthentication.Errors.{AuthenticationFailed, InvalidToken}
  alias AshAuthentication.Firebase.TokenVerifier.KeyStoreMock
  alias AshAuthentication.Strategy.FirebaseTest.{OtherProjectUser, RegisterUser, SignInOnlyUser}

  @project_id "test-project"
  @kid "test-kid"

  setup_all do
    private_jwk = JOSE.JWK.generate_key({:rsa, 2048})
    public_jwk = JOSE.JWK.to_public(private_jwk)
    %{private_jwk: private_jwk, public_jwk: public_jwk}
  end

  setup :set_mox_from_context
  setup :verify_on_exit!

  setup %{public_jwk: public_jwk} do
    stub(KeyStoreMock, :get_keys, fn -> {:ok, %{@kid => public_jwk}} end)
    :ok
  end

  describe "registration_enabled?: true (default)" do
    test "creates a new user on first sign-in", %{private_jwk: jwk} do
      token = sign(claims_for("uid-create"), jwk)

      assert {:ok, user} =
               AshAuthentication.Strategy.action(
                 strategy(RegisterUser),
                 :sign_in,
                 %{"firebase_token" => token},
                 []
               )

      assert user.uid == "uid-create"
      assert user.email == "create@example.com"
    end

    test "upserts an existing user on subsequent sign-in", %{private_jwk: jwk} do
      token = sign(claims_for("uid-upsert", %{"email" => "old@example.com"}), jwk)

      {:ok, first} =
        AshAuthentication.Strategy.action(
          strategy(RegisterUser),
          :sign_in,
          %{"firebase_token" => token},
          []
        )

      updated_token = sign(claims_for("uid-upsert", %{"email" => "new@example.com"}), jwk)

      {:ok, second} =
        AshAuthentication.Strategy.action(
          strategy(RegisterUser),
          :sign_in,
          %{"firebase_token" => updated_token},
          []
        )

      assert first.id == second.id
      assert second.email == "new@example.com"
    end
  end

  describe "registration_enabled?: false" do
    test "returns the existing user when one matches the uid", %{private_jwk: jwk} do
      seed_user(SignInOnlyUser, %{uid: "uid-seeded", email: "seeded@example.com"})

      token = sign(claims_for("uid-seeded"), jwk)

      assert {:ok, user} =
               AshAuthentication.Strategy.action(
                 strategy(SignInOnlyUser),
                 :sign_in,
                 %{"firebase_token" => token},
                 []
               )

      assert user.uid == "uid-seeded"
    end

    test "returns AuthenticationFailed when no user matches and does not create one",
         %{private_jwk: jwk} do
      token = sign(claims_for("uid-unknown"), jwk)

      assert {:error, %AuthenticationFailed{}} =
               AshAuthentication.Strategy.action(
                 strategy(SignInOnlyUser),
                 :sign_in,
                 %{"firebase_token" => token},
                 []
               )

      assert {:ok, []} = Ash.read(SignInOnlyUser)
    end
  end

  describe "multiple strategies with different project_ids" do
    test "a token is accepted by the strategy whose project_id matches its aud/iss",
         %{private_jwk: jwk} do
      token = sign(claims_for("uid-other", "other-test-project", %{}), jwk)

      assert {:ok, user} =
               AshAuthentication.Strategy.action(
                 strategy(OtherProjectUser),
                 :sign_in,
                 %{"firebase_token" => token},
                 []
               )

      assert user.uid == "uid-other"
    end

    test "a token signed for one project is rejected by a strategy bound to a different project",
         %{private_jwk: jwk} do
      token = sign(claims_for("uid-cross", "other-test-project", %{}), jwk)

      assert {:error, %InvalidToken{}} =
               AshAuthentication.Strategy.action(
                 strategy(RegisterUser),
                 :sign_in,
                 %{"firebase_token" => token},
                 []
               )

      assert {:ok, []} = Ash.read(RegisterUser)
    end
  end

  describe "transformer validation" do
    test "rejects a resource whose sign_in_action_name action does not exist" do
      assert_raise Spark.Error.DslError, ~r/sign_in_with_firebase/, fn ->
        defmodule MissingSignInResource do
          use Ash.Resource,
            domain: AshAuthentication.Strategy.FirebaseTest.TestDomain,
            data_layer: Ash.DataLayer.Ets,
            extensions: [AshAuthentication, AshAuthentication.Strategy.Firebase]

          attributes do
            uuid_primary_key(:id)
            attribute(:uid, :string, public?: true, allow_nil?: false)
          end

          authentication do
            strategies do
              firebase do
                project_id("test-project")
                token_input(:firebase_token)
                registration_enabled?(false)
              end
            end
          end
        end
      end
    end

    test "rejects a sign-in action that is missing the :user_info argument" do
      assert_raise Spark.Error.DslError, ~r/user_info/, fn ->
        defmodule BadSignInArgResource do
          use Ash.Resource,
            domain: AshAuthentication.Strategy.FirebaseTest.TestDomain,
            data_layer: Ash.DataLayer.Ets,
            extensions: [AshAuthentication, AshAuthentication.Strategy.Firebase]

          attributes do
            uuid_primary_key(:id)
            attribute(:uid, :string, public?: true, allow_nil?: false)
          end

          actions do
            read :sign_in_with_firebase do
              get?(true)
            end
          end

          authentication do
            strategies do
              firebase do
                project_id("test-project")
                token_input(:firebase_token)
                registration_enabled?(false)
              end
            end
          end
        end
      end
    end
  end

  defp strategy(resource), do: AshAuthentication.Info.strategy!(resource, :firebase)

  defp seed_user(resource, attrs) do
    resource
    |> Ash.Changeset.for_create(:seed, attrs)
    |> Ash.create!()
  end

  defp claims_for(sub, overrides \\ %{}), do: claims_for(sub, @project_id, overrides)

  defp claims_for(sub, project_id, overrides) do
    now = System.os_time(:second)

    Map.merge(
      %{
        "iss" => "https://securetoken.google.com/#{project_id}",
        "aud" => project_id,
        "sub" => sub,
        "exp" => now + 3600,
        "iat" => now - 10,
        "auth_time" => now - 20,
        "email" => "create@example.com",
        "email_verified" => true
      },
      overrides
    )
  end

  defp sign(claims, jwk) do
    {_, token} = JOSE.JWS.compact(JOSE.JWT.sign(jwk, %{"alg" => "RS256", "kid" => @kid}, claims))
    token
  end
end
