defmodule AshAuthentication.Firebase.Errors.EmailNotVerifiedTest do
  use ExUnit.Case, async: true

  alias AshAuthentication.Firebase.Errors.EmailNotVerified

  test "exception/1 carries the strategy field and renders the canonical message" do
    error = EmailNotVerified.exception(strategy: :firebase)

    assert %EmailNotVerified{strategy: :firebase} = error
    assert Exception.message(error) == "Firebase email is not verified"
  end

  test "is classed as a :forbidden Splode error" do
    assert EmailNotVerified.exception(strategy: :firebase).class == :forbidden
  end
end
