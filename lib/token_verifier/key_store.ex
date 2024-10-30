defmodule AshAuthentication.Firebase.TokenVerifier.KeyStore do
  @moduledoc """
  GenServer responsible for managing Firebase public keys.
  Fetches and caches JWKs (JSON Web Keys) from Google's servers.
  """
  use GenServer
  require Logger

  @google_keys_url "https://www.googleapis.com/robot/v1/metadata/x509/securetoken@system.gserviceaccount.com"
  @default_refresh_interval :timer.minutes(30)
  @name __MODULE__
  @finch_name AshAuthentication.Firebase.Finch

  # Client API

  def start_link(opts \\ []) do
    GenServer.start_link(__MODULE__, opts, name: @name)
  end

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
      refresh_interval: refresh_interval
    }

    {:ok, state, {:continue, :fetch_keys}}
  end

  @impl true
  def handle_continue(:fetch_keys, state) do
    case fetch_google_keys() do
      {:ok, keys, expires_in} ->
        schedule_refresh(expires_in)
        {:noreply, %{state | keys: keys, last_refresh: DateTime.utc_now()}}

      {:error, reason} ->
        Logger.error("Failed to fetch Firebase public keys: #{inspect(reason)}")
        schedule_refresh(state.refresh_interval)
        {:noreply, state}
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

    case Finch.request(request, @finch_name) do
      {:ok, %{status: 200, headers: headers, body: body}} ->
        with {:ok, json_data} <- Jason.decode(body),
             {:ok, keys} <- convert_to_jose_keys(json_data),
             expires_in <- extract_max_age(headers) do
          {:ok, keys, expires_in}
        end

      {:ok, %{status: status, body: body}} ->
        {:error, "HTTP #{status}: #{body}"}

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
end
