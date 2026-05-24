defmodule AshAuthentication.Firebase.TokenVerifier.KeyStoreIntegrationTest do
  # The KeyStore registers under its module name and uses :persistent_term,
  # both of which are global. Tests in this file must run synchronously.
  use ExUnit.Case, async: false

  alias AshAuthentication.Firebase.TokenVerifier.KeyStore

  @pt_key {KeyStore, :keys}

  setup do
    # Clean up :persistent_term between tests so prior keys do not leak in.
    :persistent_term.erase(@pt_key)

    # Test env runs with the mock key_store, so the application does not start
    # the bundled Finch pool — start it here for the duration of the test.
    start_supervised!({Finch, name: AshAuthentication.Firebase.Finch})

    bypass = Bypass.open()
    url = "http://localhost:#{bypass.port}/keys"

    %{bypass: bypass, url: url}
  end

  defp generate_pem do
    {_, pem} =
      {:rsa, 2048}
      |> JOSE.JWK.generate_key()
      |> JOSE.JWK.to_public()
      |> JOSE.JWK.to_pem()

    pem
  end

  defp start_keystore(opts) do
    pid = start_supervised!({KeyStore, opts})
    # Wait for handle_continue(:fetch_keys, ...) to run by querying state.
    # GenServer.call is processed after handle_continue completes.
    :sys.get_state(pid)
    pid
  end

  describe "200 OK" do
    test "loads valid PEMs into persistent_term", %{bypass: bypass, url: url} do
      pem = generate_pem()

      Bypass.expect_once(bypass, "GET", "/keys", fn conn ->
        conn
        |> Plug.Conn.put_resp_header("cache-control", "public, max-age=3600")
        |> Plug.Conn.put_resp_content_type("application/json")
        |> Plug.Conn.resp(200, Jason.encode!(%{"kid-1" => pem, "kid-2" => pem}))
      end)

      start_keystore(url: url)

      assert {:ok, %{"kid-1" => %JOSE.JWK{}, "kid-2" => %JOSE.JWK{}}} = KeyStore.get_keys()
    end

    test "partial-failure: keeps valid keys, drops garbage entries",
         %{bypass: bypass, url: url} do
      pem = generate_pem()

      Bypass.expect_once(bypass, "GET", "/keys", fn conn ->
        Plug.Conn.resp(conn, 200, Jason.encode!(%{"kid-1" => pem, "kid-2" => "not a PEM"}))
      end)

      start_keystore(url: url)

      assert {:ok, keys} = KeyStore.get_keys()
      assert Map.keys(keys) == ["kid-1"]
    end

    test "all-garbage response leaves persistent_term at :not_initialized",
         %{bypass: bypass, url: url} do
      Bypass.expect(bypass, "GET", "/keys", fn conn ->
        Plug.Conn.resp(conn, 200, Jason.encode!(%{"kid-1" => "junk", "kid-2" => 42}))
      end)

      start_keystore(url: url, refresh_interval: :timer.hours(1))

      assert {:error, :not_initialized} = KeyStore.get_keys()
    end
  end

  describe "Cache-Control parsing (regression for refresh_interval / max-age floor)" do
    test "honors max-age=600 by scheduling the next refresh at 600s",
         %{bypass: bypass, url: url} do
      pem = generate_pem()

      Bypass.expect_once(bypass, "GET", "/keys", fn conn ->
        conn
        |> Plug.Conn.put_resp_header("cache-control", "public, max-age=600")
        |> Plug.Conn.resp(200, Jason.encode!(%{"kid-1" => pem}))
      end)

      pid = start_keystore(url: url)
      state = :sys.get_state(pid)

      assert state.refresh_timer
      remaining = Process.read_timer(state.refresh_timer)
      # 600s ± slop. Should be well above 60s (the floor) and at most 600_000ms.
      assert remaining > 590_000 and remaining <= 600_000
    end

    test "falls back to :refresh_interval option when Cache-Control is absent",
         %{bypass: bypass, url: url} do
      pem = generate_pem()

      # Plug adds a default `cache-control: max-age=0, private, must-revalidate`
      # header; delete it so we exercise the no-Cache-Control branch.
      Bypass.expect_once(bypass, "GET", "/keys", fn conn ->
        conn
        |> Plug.Conn.delete_resp_header("cache-control")
        |> Plug.Conn.resp(200, Jason.encode!(%{"kid-1" => pem}))
      end)

      pid = start_keystore(url: url, refresh_interval: 5_000)
      state = :sys.get_state(pid)

      assert state.refresh_timer
      remaining = Process.read_timer(state.refresh_timer)
      # Should be ~5_000ms — well below the 30-minute default and the 60s floor.
      assert remaining > 1_000 and remaining <= 5_000
    end

    test "floors max-age=0 to 60 seconds", %{bypass: bypass, url: url} do
      pem = generate_pem()

      Bypass.expect_once(bypass, "GET", "/keys", fn conn ->
        conn
        |> Plug.Conn.put_resp_header("cache-control", "max-age=0")
        |> Plug.Conn.resp(200, Jason.encode!(%{"kid-1" => pem}))
      end)

      pid = start_keystore(url: url)
      state = :sys.get_state(pid)

      remaining = Process.read_timer(state.refresh_timer)
      # 60s ± slop.
      assert remaining > 55_000 and remaining <= 60_000
    end
  end

  describe "failure modes" do
    test "non-200 leaves persistent_term at :not_initialized and schedules retry",
         %{bypass: bypass, url: url} do
      Bypass.expect(bypass, "GET", "/keys", fn conn ->
        Plug.Conn.resp(conn, 500, "boom")
      end)

      pid = start_keystore(url: url)

      assert {:error, :not_initialized} = KeyStore.get_keys()
      state = :sys.get_state(pid)
      assert state.retry_attempt >= 1
      assert state.refresh_timer
    end

    test "non-200 error reason is truncated at 500 chars", %{bypass: bypass, url: url} do
      huge_body = String.duplicate("x", 5_000)

      Bypass.expect(bypass, "GET", "/keys", fn conn ->
        Plug.Conn.resp(conn, 500, huge_body)
      end)

      test_pid = self()
      handler_id = "fbtest-truncate-#{System.unique_integer([:positive])}"

      :telemetry.attach(
        handler_id,
        [:ash_authentication_firebase, :key_store, :fetch_failed],
        fn _event, _measurements, metadata, _ ->
          send(test_pid, {:fetch_failed, metadata})
        end,
        nil
      )

      on_exit(fn -> :telemetry.detach(handler_id) end)

      start_keystore(url: url)

      assert_receive {:fetch_failed, %{reason: reason}}
      assert is_binary(reason)
      # "HTTP 500: " is 10 chars, plus up to 500 chars of body = 510 max.
      assert byte_size(reason) <= 510
    end

    test "ECONNREFUSED leaves persistent_term at :not_initialized and schedules retry",
         %{bypass: bypass, url: url} do
      Bypass.down(bypass)

      pid = start_keystore(url: url)

      assert {:error, :not_initialized} = KeyStore.get_keys()
      state = :sys.get_state(pid)
      assert state.retry_attempt >= 1
    end

    test "last-known-good keys are preserved across a non-200 response",
         %{bypass: bypass, url: url} do
      pem = generate_pem()
      counter = :counters.new(1, [])

      Bypass.expect(bypass, "GET", "/keys", fn conn ->
        case :counters.get(counter, 1) do
          0 ->
            :counters.add(counter, 1, 1)

            conn
            |> Plug.Conn.put_resp_header("cache-control", "max-age=60")
            |> Plug.Conn.resp(200, Jason.encode!(%{"kid-1" => pem}))

          _ ->
            Plug.Conn.resp(conn, 500, "boom")
        end
      end)

      pid = start_keystore(url: url)

      assert {:ok, %{"kid-1" => %JOSE.JWK{}}} = KeyStore.get_keys()

      # Trigger a second fetch via cast (bypasses the 1s debounce on refresh_now).
      # The 500 response should NOT clear the existing keys.
      :ok = KeyStore.refresh_keys()
      # Block until the cast and its handle_continue have been processed.
      :sys.get_state(pid)

      assert {:ok, %{"kid-1" => %JOSE.JWK{}}} = KeyStore.get_keys()
    end
  end

  describe "restart guard" do
    test "last-known-good keys survive a GenServer restart", %{bypass: bypass, url: url} do
      pem = generate_pem()

      Bypass.expect(bypass, "GET", "/keys", fn conn ->
        Plug.Conn.resp(conn, 200, Jason.encode!(%{"kid-1" => pem}))
      end)

      pid = start_keystore(url: url)
      assert {:ok, %{"kid-1" => %JOSE.JWK{}}} = KeyStore.get_keys()

      # Tear down the GenServer; persistent_term keeps the keys.
      :ok = stop_supervised!(KeyStore)

      assert {:ok, %{"kid-1" => %JOSE.JWK{}}} = KeyStore.get_keys()
      _ = pid
    end
  end

  describe "refresh_now/0 when GenServer is not running" do
    test "returns {:error, :not_started} instead of crashing" do
      # No start_keystore here — the bundled KeyStore is not supervised in
      # the test env (mock key_store) and we haven't started it manually.
      assert {:error, :not_started} = KeyStore.refresh_now()
    end
  end
end
