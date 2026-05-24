defmodule AshAuthentication.Strategy.FirebaseTest do
  use ExUnit.Case, async: false

  import Mox

  alias AshAuthentication.Errors.{AuthenticationFailed, InvalidToken}
  alias AshAuthentication.Firebase.Errors.EmailNotVerified
  alias AshAuthentication.Firebase.TokenVerifier.KeyStoreMock

  alias AshAuthentication.Strategy.FirebaseTest.{
    BlankSecretUser,
    OtherProjectUser,
    RegisterUser,
    SignInOnlyUser,
    UnverifiedEmailUser
  }

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
    stub(KeyStoreMock, :refresh_now, fn -> :ok end)
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

  describe "email verification" do
    test "rejects a token whose email_verified claim is false", %{private_jwk: jwk} do
      claims = claims_for("uid-unverified", %{"email_verified" => false})
      token = sign(claims, jwk)

      assert {:error, %EmailNotVerified{strategy: :firebase}} =
               AshAuthentication.Strategy.action(
                 strategy(RegisterUser),
                 :sign_in,
                 %{"firebase_token" => token},
                 []
               )

      assert {:ok, []} = Ash.read(RegisterUser)
    end

    test "accepts a token whose email_verified claim is true", %{private_jwk: jwk} do
      token = sign(claims_for("uid-verified", %{"email_verified" => true}), jwk)

      assert {:ok, user} =
               AshAuthentication.Strategy.action(
                 strategy(RegisterUser),
                 :sign_in,
                 %{"firebase_token" => token},
                 []
               )

      assert user.uid == "uid-verified"
    end

    test "accepts a token with no email claim regardless of email_verified",
         %{private_jwk: jwk} do
      claims =
        "uid-no-email"
        |> claims_for()
        |> Map.drop(["email", "email_verified"])

      token = sign(claims, jwk)

      assert {:ok, user} =
               AshAuthentication.Strategy.action(
                 strategy(RegisterUser),
                 :sign_in,
                 %{"firebase_token" => token},
                 []
               )

      assert user.uid == "uid-no-email"
      assert user.email == nil
    end

    test "accepts a token with email_verified: false when require_email_verified?: false",
         %{private_jwk: jwk} do
      claims = claims_for("uid-opt-out", %{"email_verified" => false})
      token = sign(claims, jwk)

      assert {:ok, user} =
               AshAuthentication.Strategy.action(
                 strategy(UnverifiedEmailUser),
                 :sign_in,
                 %{"firebase_token" => token},
                 []
               )

      assert user.uid == "uid-opt-out"
    end
  end

  describe "token input extraction" do
    test "accepts the token when supplied under an atom key", %{private_jwk: jwk} do
      token = sign(claims_for("uid-atom-key"), jwk)

      assert {:ok, user} =
               AshAuthentication.Strategy.action(
                 strategy(RegisterUser),
                 :sign_in,
                 %{firebase_token: token},
                 []
               )

      assert user.uid == "uid-atom-key"
    end

    test "returns InvalidToken when the params do not contain the token" do
      assert {:error, %InvalidToken{}} =
               AshAuthentication.Strategy.action(
                 strategy(RegisterUser),
                 :sign_in,
                 %{},
                 []
               )
    end
  end

  describe "project_id secret" do
    test "returns InvalidToken when the project_id secret resolves to a blank string",
         %{private_jwk: jwk} do
      token = sign(claims_for("uid-blank-secret"), jwk)

      assert {:error, %InvalidToken{}} =
               AshAuthentication.Strategy.action(
                 strategy(BlankSecretUser),
                 :sign_in,
                 %{"firebase_token" => token},
                 []
               )

      assert {:ok, []} = Ash.read(BlankSecretUser)
    end
  end

  describe "telemetry" do
    test "emits :token_rejected with the verifier reason when a token is rejected",
         %{private_jwk: jwk} do
      handler_id = "fbtest-#{System.unique_integer([:positive])}"
      test_pid = self()

      :telemetry.attach(
        handler_id,
        [:ash_authentication_firebase, :strategy, :token_rejected],
        fn _event, measurements, metadata, _ ->
          send(test_pid, {:telemetry, measurements, metadata})
        end,
        nil
      )

      on_exit(fn -> :telemetry.detach(handler_id) end)

      token = sign(claims_for("uid-bad-iss", "other-test-project", %{}), jwk)

      assert {:error, %InvalidToken{}} =
               AshAuthentication.Strategy.action(
                 strategy(RegisterUser),
                 :sign_in,
                 %{"firebase_token" => token},
                 []
               )

      assert_receive {:telemetry, %{count: 1},
                      %{reason: :invalid_issuer, strategy: :firebase}}
    end
  end

  describe "transformer defaults" do
    test "defaults register_action_name to :register_with_<name>" do
      assert strategy(RegisterUser).register_action_name == :register_with_firebase
    end

    test "defaults sign_in_action_name to :sign_in_with_<name>" do
      assert strategy(SignInOnlyUser).sign_in_action_name == :sign_in_with_firebase
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
