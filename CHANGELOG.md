# Changelog

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
