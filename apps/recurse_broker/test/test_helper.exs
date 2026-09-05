# F002 T079/T080 bring property tests into the broker suite; ExUnit itself
# doesn't need any extra start args — `ExUnitProperties` / `StreamData` are
# loaded via `use ExUnitProperties` inside each property module.
#
# T081 + T079 mutate `Application.put_env(:recurse_broker, ...)` and stand
# up GenServers under their module-registered names, so those tests run
# `async: false`. The default `ExUnit.start()` honors each module's
# `async:` flag — no change needed here.
ExUnit.start()
