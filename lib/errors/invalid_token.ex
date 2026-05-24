defmodule AshAuthentication.Firebase.Errors.InvalidToken do
  @moduledoc """
  The Firebase ID token failed verification.

  The `:reason` field carries the specific failure (see `t:reason/0`).
  Callers should treat this as opaque at the boundary; it is primarily
  intended for logging and telemetry.
  """
  use Splode.Error, fields: [:reason], class: :unauthorized

  @type reason ::
          :invalid_token
          | :invalid_project_id
          | :invalid_header
          | :key_not_found
          | :invalid_signature
          | :malformed_payload
          | :invalid_issuer
          | :invalid_audience
          | :expired
          | :invalid_sub
          | :invalid_iat
          | :invalid_auth_time

  @type t :: %__MODULE__{reason: reason()}

  @spec message(t()) :: String.t()
  def message(%{reason: reason}),
    do: "Firebase token verification failed: #{reason}"
end
