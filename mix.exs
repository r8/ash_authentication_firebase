defmodule AshAuthentication.Firebase.MixProject do
  use Mix.Project

  @version "0.2.0"
  @source "https://github.com/r8/ash_authentication_firebase"

  def project do
    [
      app: :ash_authentication_firebase,
      version: @version,
      elixir: "~> 1.15",
      start_permanent: Mix.env() == :prod,
      description: description(),
      package: package(),
      docs: docs(),
      deps: deps()
    ]
  end

  # Run "mix help compile.app" to learn about applications.
  def application do
    [
      mod: {AshAuthentication.Firebase, []},
      extra_applications: [:logger]
    ]
  end

  # Run "mix help deps" to learn about dependencies.
  defp deps do
    [
      {:ash_authentication, "~> 3.11"},
      {:jose, ">= 1.10.0"},
      {:jason, ">= 1.4.0"},
      {:finch, ">= 0.13.0"},
      {:ex_doc, ">= 0.0.0", only: :dev, runtime: false},
      {:credo, "~> 1.7", only: [:dev, :test], runtime: false}
    ]
  end

  defp docs do
    [
      source_url: @source,
      source_ref: "v#{@version}",
      main: "readme",
      extras: ["README.md"]
    ]
  end

  defp description do
    """
    Firebase token authentication strategy for AshAuthentication.
    """
  end

  defp package do
    [
      maintainers: ["Sergey Storchay"],
      licenses: ["MIT"],
      links: %{"Source" => @source}
    ]
  end
end
