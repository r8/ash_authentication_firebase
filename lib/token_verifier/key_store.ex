defmodule AshAuthentication.Firebase.TokenVerifier.KeyStore do
  @moduledoc """
  GenServer responsible for managing Firebase public keys.
  Fetches and caches JWKs (JSON Web Keys) from Google's servers.
  """
  use GenServer
  @behaviour AshAuthentication.Firebase.TokenVerifier.KeyStoreBehaviour
  require Logger

  @google_keys_url "https://www.googleapis.com/robot/v1/metadata/x509/securetoken@system.gserviceaccount.com"
  @default_refresh_interval :timer.minutes(30)
  @initial_retry :timer.seconds(1)
  @max_retry :timer.minutes(5)
  @request_timeout :timer.seconds(10)
  @refresh_min_interval :timer.seconds(1)
  @max_age_seconds 86_400
  @min_age_seconds 60
  @name __MODULE__
  @telemetry_prefix [:ash_authentication_firebase, :key_store]
  @pt_key {__MODULE__, :keys}

  # Client API

  @doc """
  Starts the key store GenServer and registers it under this module's name.

  Options:

    * `:refresh_interval` — fallback interval, in milliseconds, between
      background refreshes when Google's `Cache-Control: max-age` header is
      missing or unparseable. Defaults to 30 minutes.
    * `:url` — JWKS endpoint to fetch. Defaults to Google's public key URL;
      overridable primarily for tests.

  Typically started by the library's application supervisor — host
  applications do not need to invoke this directly.
  """
  @spec start_link(keyword()) :: GenServer.on_start()
  def start_link(opts \\ []) do
    GenServer.start_link(__MODULE__, opts, name: @name)
  end

  @impl AshAuthentication.Firebase.TokenVerifier.KeyStoreBehaviour
  def get_keys do
    :persistent_term.get(@pt_key, {:error, :not_initialized})
  end

  @doc """
  Asynchronously queues a key refresh.

  Fire-and-forget cast; returns `:ok` immediately without waiting for the
  fetch to complete. Intended for internal use by the scheduled-refresh
  timer — callers that need to know whether the refresh succeeded should use
  `refresh_now/0` instead.
  """
  @spec refresh_keys() :: :ok
  def refresh_keys do
    GenServer.cast(@name, :refresh_keys)
  end

  @impl AshAuthentication.Firebase.TokenVerifier.KeyStoreBehaviour
  def refresh_now do
    GenServer.call(@name, :refresh_now, @request_timeout + :timer.seconds(2))
  catch
    :exit, {:timeout, _} -> {:error, :timeout}
    :exit, {:noproc, _} -> {:error, :not_started}
    :exit, reason -> {:error, {:key_store_exit, reason}}
  end

  # Server Callbacks

  @impl true
  def init(opts) do
    refresh_interval = Keyword.get(opts, :refresh_interval, @default_refresh_interval)
    url = Keyword.get(opts, :url, @google_keys_url)

    # Restart guard: only seed the bootstrap error if no value has ever been
    # written. On a process restart, the prior {:ok, keys} keeps serving reads
    # until the new fetch completes.
    case :persistent_term.get(@pt_key, :__absent__) do
      :__absent__ -> :persistent_term.put(@pt_key, {:error, :not_initialized})
      _ -> :ok
    end

    state = %{
      last_refresh: nil,
      last_refresh_attempt_at: nil,
      refresh_interval: refresh_interval,
      retry_attempt: 0,
      refresh_timer: nil,
      url: url
    }

    {:ok, state, {:continue, :fetch_keys}}
  end

  @impl true
  def handle_continue(:fetch_keys, state) do
    {_result, new_state} = do_fetch_and_update(state)
    {:noreply, new_state}
  end

  @impl true
  def handle_cast(:refresh_keys, state) do
    {:noreply, state, {:continue, :fetch_keys}}
  end

  @impl true
  def handle_info(:refresh_keys, state) do
    {:noreply, state, {:continue, :fetch_keys}}
  end

  @impl true
  def handle_call(:refresh_now, _from, state) do
    if recent_attempt?(state) do
      {:reply, :ok, state}
    else
      {result, new_state} = do_fetch_and_update(state)
      {:reply, result, new_state}
    end
  end

  defp recent_attempt?(%{last_refresh_attempt_at: nil}), do: false

  defp recent_attempt?(%{last_refresh_attempt_at: at}) do
    System.monotonic_time(:millisecond) - at < @refresh_min_interval
  end

  defp do_fetch_and_update(state) do
    now = System.monotonic_time(:millisecond)

    case fetch_google_keys(state.url, state.refresh_interval) do
      {:ok, keys, expires_in} ->
        maybe_put_keys(keys)

        :telemetry.execute(
          @telemetry_prefix ++ [:fetched],
          %{
            retry_attempt: state.retry_attempt,
            keys_count: map_size(keys),
            expires_in: expires_in
          },
          %{}
        )

        new_timer = reschedule_refresh(state.refresh_timer, expires_in)

        {:ok,
         %{
           state
           | last_refresh: DateTime.utc_now(),
             last_refresh_attempt_at: now,
             retry_attempt: 0,
             refresh_timer: new_timer
         }}

      {:error, reason} = error ->
        delay = backoff_delay(state.retry_attempt)
        next_attempt = state.retry_attempt + 1

        Logger.error(
          "Failed to fetch Firebase public keys: #{inspect(reason)}; " <>
            "retrying in #{delay}ms (attempt #{next_attempt})"
        )

        :telemetry.execute(
          @telemetry_prefix ++ [:fetch_failed],
          %{retry_attempt: next_attempt, delay: delay},
          %{reason: reason}
        )

        new_timer = reschedule_refresh(state.refresh_timer, delay)

        {error,
         %{
           state
           | last_refresh_attempt_at: now,
             retry_attempt: next_attempt,
             refresh_timer: new_timer
         }}
    end
  end

  # Private Functions

  defp maybe_put_keys(keys) do
    new = {:ok, keys}

    case :persistent_term.get(@pt_key, :__absent__) do
      ^new -> :ok
      _ -> :persistent_term.put(@pt_key, new)
    end
  end

  defp fetch_google_keys(url, refresh_fallback) do
    request = Finch.build(:get, url, [{"accept", "application/json"}])

    case Finch.request(request, AshAuthentication.Firebase.Finch,
           receive_timeout: @request_timeout
         ) do
      {:ok, %{status: 200, headers: headers, body: body}} ->
        with {:ok, json_data} <- Jason.decode(body),
             {:ok, keys} <- convert_to_jose_keys(json_data),
             expires_in <- extract_max_age(headers, refresh_fallback) do
          {:ok, keys, expires_in}
        end

      {:ok, %{status: status, body: body}} ->
        {:error, "HTTP #{status}: #{body}"}

      {:error, %Mint.TransportError{reason: :timeout}} ->
        {:error, :timeout}

      {:error, reason} ->
        {:error, reason}
    end
  end

  @doc false
  def convert_to_jose_keys(json_data) when is_map(json_data) do
    keys =
      for {key, value} <- json_data,
          is_binary(key),
          {:ok, jwk} <- [pem_to_jwk(value)],
          into: %{},
          do: {key, jwk}

    if map_size(keys) > 0 do
      {:ok, keys}
    else
      {:error, :no_valid_keys}
    end
  end

  def convert_to_jose_keys(_), do: {:error, :invalid_key_response}

  defp pem_to_jwk(value) when is_binary(value) and byte_size(value) > 0 do
    case JOSE.JWK.from_pem(value) do
      %JOSE.JWK{} = jwk -> {:ok, jwk}
      _ -> :error
    end
  rescue
    _ -> :error
  end

  defp pem_to_jwk(_), do: :error

  @doc false
  def extract_max_age(headers, fallback) do
    headers
    |> Enum.find(fn {key, _} -> String.downcase(to_string(key)) == "cache-control" end)
    |> case do
      {_, value} ->
        case Regex.run(~r/max-age="?(\d+)"?/, to_string(value)) do
          [_, seconds] ->
            seconds
            |> String.to_integer()
            |> max(@min_age_seconds)
            |> min(@max_age_seconds)
            |> :timer.seconds()

          nil ->
            fallback
        end

      nil ->
        fallback
    end
  end

  defp reschedule_refresh(prev_timer, interval) do
    cancel_pending_timer(prev_timer)
    Process.send_after(self(), :refresh_keys, interval)
  end

  defp cancel_pending_timer(nil), do: :ok

  defp cancel_pending_timer(ref) do
    case Process.cancel_timer(ref) do
      false ->
        # Timer already fired; drain the message if it's still in the mailbox
        # so we don't double-fetch.
        receive do
          :refresh_keys -> :ok
        after
          0 -> :ok
        end

      _remaining_ms ->
        :ok
    end
  end

  defp backoff_delay(attempt) do
    # 1s << 9 ≈ 8.5min already exceeds @max_retry (5min), so further shifts are no-ops.
    # Cap the shift to keep Bitwise.bsl bounded as attempt grows during sustained outages.
    shift = min(attempt, 9)
    capped = min(@initial_retry * Bitwise.bsl(1, shift), @max_retry)
    :rand.uniform(capped)
  end
end
