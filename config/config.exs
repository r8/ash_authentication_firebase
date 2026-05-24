import Config

# Logger metadata keys emitted by this library. Declared here so Credo's
# Logger.Metadata check recognises them and so the keys appear in this
# library's own test output. Host applications have their own logger config
# and are unaffected — they should add these keys to their own
# `:default_formatter` metadata list if they want to surface them.
config :logger, :default_formatter, metadata: [:reason, :strategy]

if File.exists?(Path.join(__DIR__, "#{config_env()}.exs")) do
  import_config "#{config_env()}.exs"
end
