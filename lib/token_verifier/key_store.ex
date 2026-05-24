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
  @name __MODULE__
  @telemetry_prefix [:ash_authentication_firebase, :key_store]

  # Client API

  def start_link(opts \\ []) do
    GenServer.start_link(__MODULE__, opts, name: @name)
  end

  @impl AshAuthentication.Firebase.TokenVerifier.KeyStoreBehaviour
  def get_keys do
    GenServer.call(@name, :get_keys)
  end

  def refresh_keys do
    GenServer.cast(@name, :refresh_keys)
  end

  # Server Callbacks

  @impl true
  def init(opts) do
    refresh_interval = Keyword.get(opts, :refresh_interval, @default_refresh_interval)

    state = %{
      keys: %{},
      last_refresh: nil,
      refresh_interval: refresh_interval,
      retry_attempt: 0
    }

    {:ok, state, {:continue, :fetch_keys}}
  end

  @impl true
  def handle_continue(:fetch_keys, state) do
    case fetch_google_keys() do
      {:ok, keys, expires_in} ->
        :telemetry.execute(
          @telemetry_prefix ++ [:fetched],
          %{
            retry_attempt: state.retry_attempt,
            keys_count: map_size(keys),
            expires_in: expires_in
          },
          %{}
        )

        schedule_refresh(expires_in)
        {:noreply, %{state | keys: keys, last_refresh: DateTime.utc_now(), retry_attempt: 0}}

      {:error, reason} ->
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

        schedule_refresh(delay)
        {:noreply, %{state | retry_attempt: next_attempt}}
    end
  end

  @impl true
  def handle_call(:get_keys, _from, %{keys: keys} = state) do
    {:reply, {:ok, keys}, state}
  end

  @impl true
  def handle_cast(:refresh_keys, state) do
    {:noreply, state, {:continue, :fetch_keys}}
  end

  @impl true
  def handle_info(:refresh_keys, state) do
    {:noreply, state, {:continue, :fetch_keys}}
  end

  # Private Functions

  defp fetch_google_keys do
    request = Finch.build(:get, @google_keys_url, [{"accept", "application/json"}])

    case Finch.request(request, AshAuthentication.Firebase.finch_name(),
           receive_timeout: @request_timeout
         ) do
      {:ok, %{status: 200, headers: headers, body: body}} ->
        with {:ok, json_data} <- Jason.decode(body),
             {:ok, keys} <- convert_to_jose_keys(json_data),
             expires_in <- extract_max_age(headers) do
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

  defp convert_to_jose_keys(json_data) do
    keys =
      json_data
      |> Enum.map(fn {key, value} ->
        case JOSE.JWK.from_pem(value) do
          [] -> {key, nil}
          jwk -> {key, jwk}
        end
      end)
      |> Enum.filter(fn {_, value} -> not is_nil(value) end)
      |> Map.new()

    if map_size(keys) > 0 do
      {:ok, keys}
    else
      {:error, :no_valid_keys}
    end
  end

  defp extract_max_age(headers) do
    headers
    |> Enum.find(fn {key, _} -> String.downcase(to_string(key)) == "cache-control" end)
    |> case do
      {_, value} ->
        value
        |> to_string()
        |> String.split(",")
        |> Enum.find(&String.contains?(&1, "max-age="))
        |> case do
          nil ->
            @default_refresh_interval

          directive ->
            directive
            |> String.trim()
            |> String.split("=")
            |> List.last()
            |> String.to_integer()
            |> :timer.seconds()
        end

      nil ->
        @default_refresh_interval
    end
  end

  defp schedule_refresh(interval) do
    Process.send_after(self(), :refresh_keys, interval)
  end

  defp backoff_delay(attempt) do
    # 1s << 9 ≈ 8.5min already exceeds @max_retry (5min), so further shifts are no-ops.
    # Cap the shift to keep Bitwise.bsl bounded as attempt grows during sustained outages.
    shift = min(attempt, 9)
    capped = min(@initial_retry * Bitwise.bsl(1, shift), @max_retry)
    :rand.uniform(capped)
  end
end
