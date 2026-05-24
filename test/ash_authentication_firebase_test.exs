defmodule AshAuthenticationFirebaseTest do
  use ExUnit.Case, async: false

  describe "supervision tree" do
    test "the Firebase supervisor is running" do
      assert is_pid(Process.whereis(AshAuthentication.Firebase.Supervisor))
    end

    test "the bundled KeyStore is not started when a custom :key_store is configured" do
      # In the test env, config sets :key_store to KeyStoreMock, so the
      # real KeyStore must not be started by the application supervisor —
      # otherwise it would issue live HTTP requests to Google during tests.
      assert Application.get_env(:ash_authentication_firebase, :key_store) ==
               AshAuthentication.Firebase.TokenVerifier.KeyStoreMock

      assert Process.whereis(AshAuthentication.Firebase.TokenVerifier.KeyStore) == nil
    end
  end
end
