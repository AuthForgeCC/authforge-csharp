# AuthForge SDK: AI Agent Reference

> This file is optimized for AI coding agents (Cursor, Copilot, Claude Code, etc.).
> It contains everything needed to correctly integrate AuthForge licensing into a project.

## What AuthForge does

AuthForge is a license key validation service. Your app activates online: it sends a license key + hardware ID to `POST /auth/validate`, and the server checks revocation, expiry, HWID, and credits, then returns a cryptographically signed session. By default the app then runs through the grace period: it keeps running on that signed session without contacting AuthForge until the session TTL expires (default 24h, server clamps to 1h through 7d). Optionally, enable online check-ins (periodic `POST /auth/heartbeat`) for fast revocation and concurrent-use detection. When a check fails (revoked, expired, or grace period over), you handle it (typically exit the app).

There is also a **separate** mode for machines that can never reach the internet: **offline license files (`.authforge`)**. The operator mints a signed file in the AuthForge cloud; `LoginFromFile()` verifies it locally with the app public key and the machine HWID, with zero network calls. Do not ship the App Secret in those builds (pass `""`). Only use it when the user explicitly asks for air-gapped / offline-file licensing. The default integration is always online `Login()` + grace period. To collect the HWID for a bound file, write an **activation request** (`.authforge-request`) with `CreateActivationRequest`. It is not a license, is not signed, and does not mint anything. Prefer it over printing the raw HWID.

A third mode, also **separate** from air-gapped files, is **self-serve offline activation** for one-time-purchase apps: `ActivateOffline(licenseKey, path)` makes one online call (`POST /auth/offline/activate`) that returns a lifetime `.authforge` file bound to this machine's HWID, verifies it locally, saves it and starts an offline session; later launches use `LoginFromFile(path)` with no network. Unlike air-gapped builds, this mode **needs the App Secret** in the build. The app must have self-serve offline activation enabled, and the license must be perpetual and seat-limited. Only use it when the user asks for "activate once, then run offline" licensing.

## Installation

Prefer **`dotnet add package AuthForge`** from [NuGet](https://www.nuget.org/packages/AuthForge/). Targets .NET 6+ (see the `.csproj` for package references such as `BouncyCastle.Cryptography`). You can instead copy `AuthForgeClient.cs`, `AuthForgeClient.Offline.cs`, `AuthForgeClient.OfflineActivation.cs` and `AuthForgeException.cs` if you truly need a source-only integration and mirror its dependencies yourself.

## Minimal working integration

```csharp
using System;
using System.Threading;
using AuthForge;

// Cancelled when the license is lost; the main loop watches it, saves work, then exits.
using var licenseLost = new CancellationTokenSource();

void OnFailure(string reason, Exception? exception)
{
    if (reason == "heartbeat_failed" && exception is AuthForgeException { IsTransient: true })
        return; // network blip / rate_limited: the SDK checks in again next interval
    Console.Error.WriteLine($"AuthForge: {reason}");
    if (exception != null)
        Console.Error.WriteLine(exception);
    licenseLost.Cancel(); // runs on the heartbeat thread: signal, do not Environment.Exit here
}

var client = new AuthForgeClient(
    appId: "YOUR_APP_ID",
    appSecret: "YOUR_APP_SECRET",
    publicKey: "YOUR_PUBLIC_KEY", // required: base64 Ed25519 key from the dashboard
    onFailure: OnFailure
);

Console.Write("Enter license key: ");
var licenseKey = Console.ReadLine() ?? string.Empty;

if (!client.Login(licenseKey))
{
    Console.Error.WriteLine("Login failed.");
    Environment.Exit(1);
}

// --- Your application code starts here ---
Console.WriteLine("Running with a valid license.");
while (!licenseLost.IsCancellationRequested)
{
    licenseLost.Token.WaitHandle.WaitOne(1000); // replace with short units of work
}
// --- Your application code ends here ---

// Save the user's work here, then stop.
client.Logout();
return 1;
```

This activates once online and then runs through the grace period with no further network traffic. To enable online check-ins for fast revocation, add `onlineHeartbeat: true` (and optionally tune `heartbeatInterval`).

## Constructor parameters

| Parameter | Type | Required | Default | Description |
|-----------|------|----------|---------|-------------|
| `appId` | `string` | yes | n/a | Application ID |
| `appSecret` | `string` | for online APIs | n/a | Application secret. Required for `Login` / `ValidateLicense` / `SelfBan` / `ActivateOffline`. Pass `""` for `LoginFromFile` only; do not ship it in air-gapped binaries. |
| `publicKey` | `string` / `IEnumerable<string>` | yes | n/a | Base64 Ed25519 public key from the dashboard (3rd positional arg; no default, so it must be supplied or the call won't compile). The string overload accepts a comma-separated trust list; an `IEnumerable<string>` overload takes a rotation set. The SDK trusts a signature matching **any** key |
| `onlineHeartbeat` | `bool` | no | `false` | `false`: after activation, run through the grace period locally (no network). `true`: periodic online check-ins via `/auth/heartbeat` for fast revocation and concurrent-use detection |
| `heartbeatInterval` | `int` | no | `900` | Seconds between background checks (minimum `10`; with online check-ins, revocations apply on the next check-in) |
| `apiBaseUrl` | `string` | no | `https://auth.authforge.cc` | API base URL |
| `onFailure` | `Action<string, Exception?>?` | no | `null` | Called on login/heartbeat failure (not used by `ValidateLicense`). If null, a transient background check failure prints a one-line warning to stderr and check-ins continue; any other failure calls `Environment.Exit(1)` |
| `requestTimeout` | `int` | no | `15` | HTTP timeout (seconds) |
| `ttlSeconds` | `int?` | no | `null` (server default: 86400, 24h) | Requested grace period duration in seconds (the session token lifetime). Server clamps to `[3600, 604800]` (1h to 7d); preserved across online check-in refreshes. |
| `hwidOverride` | `string?` | no | `null` | Optional custom HWID/subject string. When set to a non-empty value (for example `tg:123456789`), the SDK sends it instead of generating a machine fingerprint. |

For Telegram/Discord bot flows, prefer immutable IDs (`tg:<user_id>`, `discord:<user_id>`) instead of usernames.

## Migrating from heartbeatMode

Earlier versions required a `string heartbeatMode` ("LOCAL" or "SERVER") as the 4th constructor parameter. Migration:

- `heartbeatMode: "LOCAL"` maps to the default grace period behavior: remove the argument.
- `heartbeatMode: "SERVER"` maps to `onlineHeartbeat: true`.

The old string constructors still work and behave identically, but emit an obsolete warning (CS0618). The `HeartbeatMode` property ("SERVER"/"LOCAL") is also obsolete; read `bool OnlineHeartbeat` instead.

```csharp
// Before
new AuthForgeClient(appId, appSecret, publicKey, "SERVER");
// After
new AuthForgeClient(appId, appSecret, publicKey, onlineHeartbeat: true);
```

## Billing model

- Each `Login()` or `ValidateLicense()` calls `/auth/validate` and costs **1 credit**.
- Online check-ins cost **1 credit per 10 successful calls** (billed on every 10th heartbeat). The default grace period behavior makes no network calls after activation and costs nothing.
- **1 offline file mint = 1 credit** (charged to the operator when the file is minted). `LoginFromFile()` / `VerifyLicenseFile()` cost nothing.
- **1 new offline activation = 2 credits; re-activating the same machine is free.** Charged to the app owner when `ActivateOffline()` succeeds for a new machine; a refused activation costs nothing.
- Keep `heartbeatInterval` at or above 10 seconds. `/auth/heartbeat` is limited to 6 requests/minute per license key; cost still scales with how many check-ins you send.
- With online check-ins, revocations take effect on the **next** check-in regardless of interval. With the default grace period behavior, a revocation is only noticed at the next online activate/validate.

## Methods

| Method | Returns | Description |
|--------|---------|-------------|
| `Login(string licenseKey)` | `bool` | Activates online, verifies signatures, starts the background thread |
| `ValidateLicense(string licenseKey)` | `ValidateLicenseResult` | Same validate + signatures as `Login`; no session persistence or background thread; **never** calls `onFailure` or `Environment.Exit` |
| `LoginFromFile(string pathOrText)` | `bool` | Offline mode: verifies a `.authforge` file locally (no network), authenticates the client, never starts the background thread. Failures -> `onFailure("offline_login_failed", ex)` + `false`; never `Environment.Exit` |
| `ActivateOffline(string licenseKey, string? path = null)` | `bool` | Self-serve offline activation: one online call returns a lifetime HWID-bound `.authforge` file; verified locally before anything is written, saved atomically to `path` (optional, parent dirs created), then an offline session exactly as after `LoginFromFile`. Requires the App Secret (`ArgumentException` without it). Failures throw `AuthForgeException`; never calls `onFailure` or `Environment.Exit`; a failure authenticates nothing and leaves an existing session as it was |
| `VerifyLicenseFile(string pathOrText, DateTimeOffset? now = null)` | `VerifyLicenseFileResult` | Same offline checks without changing client state |
| `GetOfflineLicense()` | `OfflineLicense?` | `Jti`, `ExpiresAt`, `HwidPolicy`, … of the offline file in use |
| `GetSessionKind()` | `SessionKind?` | `SessionKind.Online`, `SessionKind.Offline`, or `null` when logged out |
| `GetHwid()` | `string` | HWID this client sends; the customer reports it so the operator can mint a bound file |
| `CreateActivationRequest(ActivationRequestOptions? options = null)` | `string` | Unsigned `.authforge-request` for this machine. No network, no secret, callable before `Login()`. Hostname omitted unless `IncludeMachineName` |
| `Logout()` | `void` | Stops the background thread and clears session state |
| `IsAuthenticated()` | `bool` | Whether a session exists |
| `GetSessionData()` | `Dictionary<string, object?>?` | Decoded payload map |
| `GetAppVariables()` | `Dictionary<string, object?>?` | App-scoped variables |
| `GetLicenseVariables()` | `Dictionary<string, object?>?` | License-scoped variables |

## Error codes the server can return

Full set: invalid_app, invalid_key, expired, revoked, hwid_mismatch, no_credits, app_burn_cap_reached, blocked, rate_limited, replay_detected, app_disabled, session_expired, revoke_requires_session, bad_request, malformed_request, demo_quota_exceeded, server_error, system_error. `/auth/offline/activate` (`ActivateOffline`) adds offline_activation_disabled, offline_activation_requires_perpetual, offline_activation_requires_seats, offline_activation_limit_reached. Unknown lowercase snake_case codes are passed through unchanged (e.g. in `ValidateLicenseResult.ErrorCode`).

Notes:
- `ActivateOffline` codes (all fatal): `offline_activation_disabled` (app has not opted in), `offline_activation_requires_perpetual` (license has an expiry), `offline_activation_requires_seats` (shared / unlimited-seat key), `offline_activation_limit_reached` (every machine slot used; HWID resets do not free them, so tell the buyer to contact the vendor). From this endpoint `hwid_mismatch` means "no free seat". SDK codes: `offline_file_rejected` (fatal; the returned file failed local verification, the verifier's reason is in `ex.Message`, nothing was written), `file_write_failed` (transient; could not save to `path`, the machine is activated and calling again is free), `unexpected_response` (transient; e.g. a success body without `file`).
- `replay_detected` is validate-only. `rate_limited` can be returned by `/auth/validate` and `/auth/heartbeat` (heartbeat is license-limited at 6/min and has no app-layer IP limit).
- `app_burn_cap_reached` means the app's configured credit burn cap is hit; `revoke_requires_session` means a pre-session self-ban tried to revoke a license (only session-authenticated self-ban can revoke).
- `session_expired` from the background thread means the grace period ended; call `Login` again to re-activate.
- Retries: only `rate_limited` (or HTTP 429 with no error code) is retried, after 2s then 5s. `no_credits`, `app_burn_cap_reached` and `demo_quota_exceeded` (also HTTP 429) fail immediately. Network failures retry once after 2s.

## Failure Handling

Background check failures call `onFailure("heartbeat_failed", ex)` with `ex` an `AuthForgeException` (`Code`, `IsTransient`, `IsFatal`). For server codes `ex.Message == ex.Code`; network failures keep the `url_error: ...` message. `AuthForgeClient.IsTransientError(code)` and `AuthForgeClient.DefinitiveErrorCodes` expose the same classification.

| Kind | Codes | SDK behavior |
|---|---|---|
| Fatal | `revoked`, `expired`, `hwid_mismatch`, `blocked`, `session_expired`, `malformed_request`, `app_disabled`, `invalid_app`, `signature_mismatch` | Clears the session (as `Logout()`) and stops background checks before `onFailure`; `IsAuthenticated()` is `false` |
| Transient | everything else: `network_error`, `timeout`, `rate_limited`, `system_error`, `server_error`, `no_credits`, `demo_quota_exceeded`, `app_burn_cap_reached`, `bad_request`, `invalid_key`, `http_error_<status>`, `unexpected_response`, unknown codes | Keeps the session and checks in again next interval; after the session TTL has passed it is reported as fatal `session_expired` |

- `hwid_mismatch` on a check-in: this HWID is no longer bound to the license (for example after an HWID reset in the dashboard).
- `blocked` on a check-in: the HWID or IP is blacklisted, or not on the app's whitelist.
- `unexpected_response`: the failed body was not a well-formed verdict (`{"status":"failed","error":"<code>"}`), e.g. a proxy answered; the message carries the raw `status` / `error`.
- Heartbeat network failures are reported once (`heartbeat_failed` with `network_error` / `timeout`), not also as `network_error`.
- Transient failures keep checking in only if `onFailure` returns; without a callback a transient failure prints a one-line stderr warning and check-ins continue, and any other failure calls `Environment.Exit(1)`.
- Thread safety: `onFailure` for `heartbeat_failed` runs on the heartbeat thread with no SDK lock held. Calling `Logout()` / `IsAuthenticated()` (or `Login()`) from it is safe; `Logout()` never waits for the thread. A late check-in response after `Logout()` / `Login()` is discarded.

```csharp
onFailure: (reason, ex) =>
{
    if (ex is AuthForgeException { IsTransient: true })
        return; // outage or overload: keep running, the SDK checks in again
    Console.Error.WriteLine($"AuthForge: {reason} ({(ex as AuthForgeException)?.Code ?? ex?.Message})");
    licenseLost.Cancel(); // the main loop saves work and exits
}
```

`Environment.Exit(1)` inside `onFailure` is a last resort: `finally` blocks on other threads do not run, so save the user's work first. In WinForms/WPF, marshal to the UI thread (`BeginInvoke`) and close the main window instead.

## Common patterns

### Reading license variables (feature gating)

```csharp
var vars = client.GetLicenseVariables();
var tier = vars != null && vars.TryGetValue("tier", out var v) ? v : null;
```

### Graceful shutdown

```csharp
client.Logout();
```

### Offline license file (air-gapped machine, only when asked)

```csharp
// Step 1 (customer machine): print the HWID so the operator can bind the file to it.
Console.WriteLine(client.GetHwid());

// Step 2 (operator): mint the .authforge file in the dashboard or via
// POST /v1/licenses/{licenseKey}/offline-files and deliver it out-of-band.

// Step 3 (customer machine): authorize with the file. No network, no check-ins.
if (!client.LoginFromFile("license.authforge"))
{
    // onFailure already received ("offline_login_failed", ArgumentException(code)) where code is one of
    // bad_armor | bad_signature | unsupported_version | malformed_payload | wrong_app | expired | hwid_mismatch
    Environment.Exit(1);
}
```

Offline file error codes (in check order): `bad_armor`, `bad_signature`, `unsupported_version`, `malformed_payload`, `wrong_app`, `expired`, `hwid_mismatch`.

### Self-serve offline activation (activate once, then offline; only when asked)

Not the air-gapped flow above: this build ships the App Secret and makes one online call per machine. Try the file first; activate only when there is no file or it does not verify (new or changed hardware).

```csharp
var licensePath = Path.Combine(
    Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "MyApp", "license.authforge");
var client = new AuthForgeClient(appId: "YOUR_APP_ID", appSecret: "YOUR_APP_SECRET", publicKey: "YOUR_PUBLIC_KEY");

if (!(File.Exists(licensePath) && client.LoginFromFile(licensePath)))
{
    var key = PromptForLicenseKey(); // app UI
    try
    {
        client.ActivateOffline(key, licensePath); // verifies, writes atomically, starts an offline session
    }
    catch (AuthForgeException ex) when (ex.Code == "offline_activation_limit_reached")
    {
        ShowError("This license is activated on its maximum number of machines. Please contact the vendor.");
        return;
    }
    catch (AuthForgeException ex)
    {
        ShowError(ex.IsTransient
            ? $"Activation failed ({ex.Code}). Check your connection and try again."
            : $"This license cannot be activated ({ex.Code}).");
        return;
    }
}
```

- Billing: 1 new offline activation = 2 credits, charged to the app owner; re-activating the same machine (reinstall, deleted file) is free and returns the identical file.
- Each license can produce files for at most `maxHwidSlots` distinct machines, ever; HWID resets do not free them.
- A refund or chargeback revokes the license online but cannot reach files already issued: the buyer keeps a lifetime file.
- With `onFailure` set, `LoginFromFile()` reports a failed file as `onFailure("offline_login_failed", ex)`; do not exit the app for that reason when falling back to `ActivateOffline()`.

### Custom error handling

Reasons passed to `onFailure` include `login_failed` and `heartbeat_failed`. For `login_failed`, a server rejection surfaces as `ArgumentException` whose message is the server error code (e.g. `invalid_key`); network and HTTP errors are `AuthForgeException` (`network_error`, `timeout`, `http_error_<status>`). For `heartbeat_failed` it is always an `AuthForgeException` (see [Failure Handling](#failure-handling)).

```csharp
onFailure: (reason, ex) =>
{
    if (reason == "heartbeat_failed" && ex is AuthForgeException { IsTransient: true })
        return;
    var code = ex is AuthForgeException afe ? afe.Code : ex?.Message;
    if (code is "invalid_key" or "expired" or "revoked")
        Console.Error.WriteLine($"License: {code}");
    licenseLost.Cancel();
}
```

## Do NOT

- Do not hardcode the app secret as a plain string literal in source: use environment variables or encrypted config
- Do not embed the App Secret in air-gapped / `LoginFromFile()` builds: pass `""`; verification only needs app id + public key. (Self-serve `ActivateOffline()` builds are the exception: that call is online and needs the secret.)
- Do not call `ActivateOffline()` on every launch: call `LoginFromFile(path)` first and activate only when there is no file or it fails
- Do not treat `ActivateOffline()`'s `hwid_mismatch` as a bad file: from that endpoint it means "no free seat"; a file that fails local checks is `offline_file_rejected`
- Do not skip `onFailure`: without it, transient check-in failures only print a stderr warning, but definitive ones (and a failed `Login`) call `Environment.Exit(1)` without your cleanup
- Do not call `Environment.Exit` from `onFailure` as the normal shutdown path: signal the main thread (a `CancellationTokenSource`, or `BeginInvoke` in a UI app) so it can save work and exit cleanly
- Do not call `Login` on every app action: call once at startup; the grace period or online check-ins handle the rest
- Do not pass the legacy `heartbeatMode` string in new code: the default already gives you the grace period, and `onlineHeartbeat: true` replaces `"SERVER"`
- Do not treat the grace period as persistent offline licensing: it is session continuation after one successful online activation, and revocations are only picked up at the next online validate or check-in
- Do not reach for `LoginFromFile()` unless the user explicitly needs air-gapped / offline-file licensing: the default is online `Login()` + grace period
- Do not expect an online revoke to disable an offline file that is already on a customer machine: the file stays valid until its own `ExpiresAt`; prefer short expiries and HWID-bound files
- Do not mint or accept `hwid.mode: "any"` files casually: anyone who copies an unbound file has a working license
- Do not call `LoginFromFile()` with another app's public key or app id: the file is rejected with `bad_signature` / `wrong_app` by design
- Do not try to build `.authforge` files client-side: only the AuthForge cloud holds the signing key; there is no BYO issuer
- Do not call `SelfBan()` or any other online method after `LoginFromFile()`: an offline session has no server session (`GetSessionKind()` is `SessionKind.Offline`), so `SelfBan()` throws `ArgumentException("offline_session")` without contacting the server and online check-ins never start; machines that can reach AuthForge should use online `Login()`
- Do not bind an offline file to an HWID reported by a different SDK or language: HWID fingerprints are not portable across SDKs, so collect the HWID from the exact SDK build that will load the file (or use the HWID override with an identifier you control)

## Activation request vectors

`activation_request_vectors.json` is generated by `authforge-node/generate_activation_request_vectors.mjs`. Regenerating it means copying the file unmodified into all six SDK repos and `platform/frontend/src/test/fixtures/activation_request_vectors.json` in the same change. The vector `sdk` value is a frozen encoding fixture, not the live SDK tag.
