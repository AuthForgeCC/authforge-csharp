# Next major release

Breaking changes deferred to the next major version. The SDKs version in lockstep on major.minor, so these ship in the same release as the other SDKs' deferred changes. When one lands, move it to `CHANGELOG.md` and delete it here.

## `Login()` fires `onFailure` once on a network failure

- **Now (1.4.x):** when `/auth/validate` is still unreachable after the network retry, `Login()` calls `onFailure("network_error", ex)` from `PostJson` and then `onFailure("login_failed", ex)`, and returns `false`. Without an `onFailure` callback the first call exits the process, so the exit reason is `network_error`. Check-in network failures already fire once (1.4.0).
- **Planned:** fire once, as `onFailure("login_failed", ex)` where `ex` is an `AuthForgeException` with `Code` `network_error` or `timeout`, matching check-ins and the C++ SDK.
- **Why deferred:** callers that react to the `network_error` reason (for example to show an offline message) would stop seeing it, and callers counting callbacks would see one instead of two.
- **Touches:** the `PostJson("/auth/validate", ...)` call in `ValidateAndStore` (`AuthForgeClient.cs`; pass `skipFailureOnNetwork: true`), a login network-failure test in `AuthForge.Tests`, `README.md` / `AGENTS.md` reason lists, AuthForgeDocs `sdk/csharp.mdx`.
