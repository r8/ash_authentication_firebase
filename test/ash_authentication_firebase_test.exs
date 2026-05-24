defmodule AshAuthenticationFirebaseTest do
  use ExUnit.Case, async: false

  alias AshAuthentication.Firebase

  describe "finch_name/0" do
    setup do
      previous = Application.get_env(:ash_authentication_firebase, :finch_name)

      on_exit(fn ->
        case previous do
          nil -> Application.delete_env(:ash_authentication_firebase, :finch_name)
          value -> Application.put_env(:ash_authentication_firebase, :finch_name, value)
        end
      end)

      :ok
    end

    test "returns the default pool name when no override is configured" do
      Application.delete_env(:ash_authentication_firebase, :finch_name)
      assert Firebase.finch_name() == AshAuthentication.Firebase.Finch
    end

    test "returns the configured value when :finch_name is set" do
      Application.put_env(:ash_authentication_firebase, :finch_name, MyApp.SharedFinch)
      assert Firebase.finch_name() == MyApp.SharedFinch
    end
  end

  describe "supervision tree" do
    test "the Firebase supervisor and its key store child are running" do
      assert is_pid(Process.whereis(AshAuthentication.Firebase.Supervisor))
      assert is_pid(Process.whereis(AshAuthentication.Firebase.TokenVerifier.KeyStore))
    end
  end
end
