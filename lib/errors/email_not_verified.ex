defmodule AshAuthentication.Firebase.Errors.EmailNotVerified do
  @moduledoc """
  Sign-in was rejected because the Firebase token's email is not verified.
  """
  use Splode.Error, fields: [:strategy], class: :forbidden

  @type t :: %__MODULE__{strategy: atom() | nil}

  @spec message(t()) :: String.t()
  def message(_), do: "Firebase email is not verified"
end
