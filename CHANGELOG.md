# Changelog

## 1.5.0

### Features

- **Self-serve offline activation: `ActivateOffline(string licenseKey, string? path = null)`.** One online call to `POST /auth/offline/activate` turns a license key into a lifetime, HWID-bound `.authforge` file. The SDK verifies the file locally (signature against the configured public key(s), app id, this machine's HWID) before writing anything, writes it byte-for-byte and atomically to `path` (temp file + rename, parent directories created) when `path` is set, and starts an offline session exactly as `LoginFromFile()` does (no background thread). Later launches use `LoginFromFile(path)` with no network.
  - Needs the App Secret (it is an online call); without it, throws the same `ArgumentException` as `Login()` before any request. Air-gapped offline files still ship with no App Secret.
  - Uses the same HWID, nonce generator, base URL, timeout and retry policy as `Login()`.
  - Failures throw `AuthForgeException`. It never calls `onFailure` or `Environment.Exit`, never writes a file that failed verification, never modifies an existing file at `path` on failure, and does not authenticate the client (an existing session is left as it was).
  - Billing: 1 new offline activation = 2 credits, charged to the app owner; re-activating the same machine is free and returns the identical file.
- New fatal codes (in `DefinitiveErrorCodes` and the known-code list): `offline_activation_disabled`, `offline_activation_requires_perpetual`, `offline_activation_requires_seats`, `offline_activation_limit_reached` (server) and `offline_file_rejected` (SDK: the returned file failed local verification; the verifier's reason, e.g. `bad_signature`, is in the message). New transient SDK code `file_write_failed` (the file could not be saved; activating again is free). A success response without `file` is `unexpected_response`.
- New source file `AuthForgeClient.OfflineActivation.cs` (add it if you vendor the sources).
- Tests against the shared `self_serve_activation_vectors.json`.

## 1.4.1

### Fixes

- **No more exit on transient failures without a callback.** Without `onFailure`, a transient background check failure (network outage, timeout, `rate_limited`, `system_error`, `no_credits`, ...) no longer calls `Environment.Exit(1)`. The SDK writes one line to stderr, `AuthForge: background check failed (<code>); retrying next interval`, keeps the session and checks in again on the next interval. Previously a brief outage killed any app that enabled online check-ins without setting a callback.
- Unchanged: without a callback, definitive failures (including the `session_expired` a transient failure becomes once the session TTL has passed) and failed `Login` calls still call `Environment.Exit(1)`.

### Docs

- The README and `AGENTS.md` examples no longer call `Environment.Exit(1)` from `onFailure`. They cancel a `CancellationTokenSource` that the main loop watches, so it can save work and exit; `Environment.Exit` is kept as a last resort after saving.

## 1.4.0

### Behavior changes for callers

- **New `AuthForgeException`** (`Code`, `IsTransient`, `IsFatal`) is the exception passed to `onFailure("heartbeat_failed", ex)`. For server codes `ex.Message` still equals the code. `AuthForgeClient.IsTransientError(code)` and `AuthForgeClient.DefinitiveErrorCodes` expose the same classification.
- **Classification**: only `revoked`, `expired`, `hwid_mismatch`, `blocked`, `session_expired`, `malformed_request`, `app_disabled`, `invalid_app` and `signature_mismatch` are definitive. Everything else is transient, including `no_credits`, `demo_quota_exceeded`, `app_burn_cap_reached`, `rate_limited`, `http_error_N`, network errors, timeouts and unknown codes.
- **Transient heartbeat failures keep checking in.** Previously the background thread stopped after any failure. A transient failure after the session TTL has passed is reported as a definitive `session_expired`.
- **Definitive heartbeat failures clear the session** (as `Logout()` does) before `onFailure` runs, so `IsAuthenticated()` is `false` inside and after the callback. Previously it stayed `true`.
- **`unexpected_response`** (transient): a failed check-in body that is not `{"status":"failed","error":"<code>"}` is no longer treated as a verdict.
- **Retry change (also affects `Login` / `ValidateLicense`)**: only `rate_limited`, or HTTP 429 with no error code, is retried (after 2s, then 5s). HTTP 429 with `no_credits`, `app_burn_cap_reached` or `demo_quota_exceeded` now fails immediately.
- **Heartbeat network failures fire `onFailure` once**, as `heartbeat_failed` with code `network_error` or `timeout`, instead of also firing `onFailure("network_error")`. `Login()` still fires both `network_error` and `login_failed`; that change is deferred to the next major (see `NEXT_MAJOR.md`).
- **Unknown server codes are passed through** (lowercase snake_case) instead of becoming `unknown_error`. This affects `ValidateLicenseResult.ErrorCode`.
- **Network and HTTP errors are `AuthForgeException`** (`network_error`, `timeout`, `http_error_N`) instead of `InvalidOperationException`. Their `Message` is unchanged (`url_error: ...`, `http_error_N`).
- `Logout()` now stops the background thread promptly and is safe to call from `onFailure` on the heartbeat thread.
