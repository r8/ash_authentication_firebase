defmodule AshAuthentication.Strategy.FirebaseTest.TestDomain do
  @moduledoc false
  use Ash.Domain, validate_config_inclusion?: false

  resources do
    allow_unregistered?(true)
  end
end

defmodule AshAuthentication.Strategy.FirebaseTest.RegisterUser do
  @moduledoc false
  use Ash.Resource,
    domain: AshAuthentication.Strategy.FirebaseTest.TestDomain,
    data_layer: Ash.DataLayer.Ets,
    extensions: [AshAuthentication, AshAuthentication.Strategy.Firebase]

  ets do
    private?(true)
  end

  attributes do
    uuid_primary_key(:id)
    attribute(:uid, :string, public?: true, allow_nil?: false)
    attribute(:email, :string, public?: true)
  end

  identities do
    identity(:unique_uid, [:uid],
      pre_check_with: AshAuthentication.Strategy.FirebaseTest.TestDomain
    )
  end

  actions do
    defaults([:read])

    create :register_with_firebase do
      argument(:user_info, :map, allow_nil?: false)
      upsert?(true)
      upsert_identity(:unique_uid)

      change(fn changeset, _ ->
        info = Ash.Changeset.get_argument(changeset, :user_info)

        changeset
        |> Ash.Changeset.change_attribute(:uid, info["uid"])
        |> Ash.Changeset.change_attribute(:email, info["email"])
      end)
    end
  end

  authentication do
    strategies do
      firebase do
        project_id("test-project")
        token_input(:firebase_token)
      end
    end
  end
end

defmodule AshAuthentication.Strategy.FirebaseTest.OtherProjectUser do
  @moduledoc false
  use Ash.Resource,
    domain: AshAuthentication.Strategy.FirebaseTest.TestDomain,
    data_layer: Ash.DataLayer.Ets,
    extensions: [AshAuthentication, AshAuthentication.Strategy.Firebase]

  ets do
    private?(true)
  end

  attributes do
    uuid_primary_key(:id)
    attribute(:uid, :string, public?: true, allow_nil?: false)
    attribute(:email, :string, public?: true)
  end

  identities do
    identity(:unique_uid, [:uid],
      pre_check_with: AshAuthentication.Strategy.FirebaseTest.TestDomain
    )
  end

  actions do
    defaults([:read])

    create :register_with_firebase do
      argument(:user_info, :map, allow_nil?: false)
      upsert?(true)
      upsert_identity(:unique_uid)

      change(fn changeset, _ ->
        info = Ash.Changeset.get_argument(changeset, :user_info)

        changeset
        |> Ash.Changeset.change_attribute(:uid, info["uid"])
        |> Ash.Changeset.change_attribute(:email, info["email"])
      end)
    end
  end

  authentication do
    strategies do
      firebase do
        project_id("other-test-project")
        token_input(:firebase_token)
      end
    end
  end
end

defmodule AshAuthentication.Strategy.FirebaseTest.SignInOnlyUser do
  @moduledoc false
  use Ash.Resource,
    domain: AshAuthentication.Strategy.FirebaseTest.TestDomain,
    data_layer: Ash.DataLayer.Ets,
    extensions: [AshAuthentication, AshAuthentication.Strategy.Firebase]

  require Ash.Query

  ets do
    private?(true)
  end

  attributes do
    uuid_primary_key(:id)
    attribute(:uid, :string, public?: true, allow_nil?: false)
    attribute(:email, :string, public?: true)
  end

  identities do
    identity(:unique_uid, [:uid],
      pre_check_with: AshAuthentication.Strategy.FirebaseTest.TestDomain
    )
  end

  actions do
    defaults([:read])

    create :seed do
      accept([:uid, :email])
    end

    read :sign_in_with_firebase do
      argument(:user_info, :map, allow_nil?: false)
      get?(true)

      prepare(fn query, _ ->
        uid_value = Ash.Query.get_argument(query, :user_info)["uid"]
        Ash.Query.filter(query, uid == ^uid_value)
      end)
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
