# AuthForge C# SDK

Official C# SDK for [AuthForge](https://authforge.cc): credit-based license key authentication with Ed25519-verified responses.

Dependencies: `BouncyCastle.Cryptography` for Ed25519 verification. Targets .NET 6+.

## How licensing works

1. **Activate**: `Login()` calls `POST /auth/validate` once. The server checks revocation, expiry, HWID binding, and credits, then returns an Ed25519-signed session.
2. **Grace period (default)**: the app keeps running on that signed session without contacting AuthForge. The grace period equals the session TTL: default 24h, and the server clamps requests to between 1h and 7d. A background thread re-verifies the signed session locally and fails with `session_expired` once the grace period ends.
3. **Online check-ins (opt-in)**: pass `onlineHeartbeat: true` and the SDK instead calls `POST /auth/heartbeat` every `heartbeatInterval` seconds. Use this when you want fast revocation and concurrent-use detection instead of waiting for the grace period to lapse.

## Features

Everything in this list ships in `AuthForgeClient.cs` today:

- **License validation** via `POST /auth/validate`, returning a signed session.
- **Ed25519 signature verification** on every `/auth/validate` and `/auth/heartbeat` response; tampered or unsigned responses are rejected.
- **Key rotation**: a single-key constructor (also accepts a comma-separated string) and an `IEnumerable<string>` rotation-set constructor. The SDK trusts a signature that matches **any** key, so you can roll the server-side signing key without breaking deployed clients.
- **Nonce anti-replay**: a fresh 128-bit nonce is sent on every request and the echoed nonce in the signed payload is checked before the response is accepted.
- **HWID fingerprinting**: deterministic device hash from MAC + CPU + disk serial, with graceful per-component fallback.
- **`hwidOverride`**: bind to any identity instead of the machine (for example `tg:<id>`, `discord:<id>`).
- **Seat enforcement**: the server binds each HWID into a license's free slots up to `maxHwidSlots`; `HwidCount` / `MaxHwidSlots` are surfaced on the validate result. A shared (unlimited-seat) key skips per-device binding.
- **Grace period by default, online check-ins on demand** (see [Grace period and online check-ins](#grace-period-and-online-check-ins)).
- **Offline license files (`.authforge`)**: `LoginFromFile()` / `VerifyLicenseFile()` verify a cloud-minted, Ed25519-signed file with zero network access for air-gapped machines.
- **Self-ban** (`SelfBan(...)`) for anti-tamper response, both pre-session and post-session.
- **Grace period duration** (`ttlSeconds`) with server-side clamping to `[3600, 604800]` (1h to 7d).
- **App variables / license variables** for feature flags and tiered licensing.
- **Automatic retries** for rate-limited and transient network failures, with a fresh nonce per retry.

## Installation

The package is **`AuthForge`** on [NuGet](https://www.nuget.org/packages/AuthForge/).

```bash
dotnet add package AuthForge
```

**Alternative:** copy `AuthForgeClient.cs`, `AuthForgeClient.Offline.cs` and `AuthForgeException.cs` into your solution if you need a source-only vendored layout (you still need the same NuGet dependencies declared in your project).

## Quick Start

```csharp
using AuthForge;

var client = new AuthForgeClient(
    appId: "YOUR_APP_ID",          // from your AuthForge dashboard
    appSecret: "YOUR_APP_SECRET",  // from your AuthForge dashboard
    publicKey: "YOUR_PUBLIC_KEY"   // base64 Ed25519 public key from dashboard
);

Console.Write("Enter license key: ");
var key = Console.ReadLine() ?? "";

if (client.Login(key))
{
    Console.WriteLine("Authenticated!");
    // Your app logic here. The app activated online and now runs through
    // the grace period (default 24h) without contacting AuthForge.
}
else
{
    Console.WriteLine("Invalid license key.");
    Environment.Exit(1);
}
```

To enable online check-ins for fast revocation:

```csharp
var client = new AuthForgeClient(
    appId: "YOUR_APP_ID",
    appSecret: "YOUR_APP_SECRET",
    publicKey: "YOUR_PUBLIC_KEY",
    onlineHeartbeat: true,      // periodic /auth/heartbeat calls
    heartbeatInterval: 900      // seconds between check-ins
);
```

## Configuration

| Parameter | Type | Default | Description |
|---|---|---|---|
| `appId` | string | required | Your application ID from the AuthForge dashboard |
| `appSecret` | string | required for online APIs; `""` for `LoginFromFile` only | Your application secret from the AuthForge dashboard. Do not ship it in air-gapped binaries. |
| `publicKey` | `string` / `IEnumerable<string>` | required | App Ed25519 public key(s) (base64) from dashboard. The single-string overload accepts a comma-separated trust list; the `IEnumerable<string>` overload takes a rotation set. The SDK trusts a signature matching **any** key (see [Key rotation](#key-rotation)). |
| `onlineHeartbeat` | bool | `false` | `false`: run through the grace period after activation, no network. `true`: enable online check-ins via `/auth/heartbeat` (see below) |
| `heartbeatInterval` | int | `900` | Seconds between background checks (minimum `10`; default 15 min). Applies to both the local grace period re-verification and online check-ins |
| `apiBaseUrl` | string | `https://auth.authforge.cc` | API endpoint |
| `onFailure` | Action\<string, Exception?\> | `null` | Callback on auth failure |
| `requestTimeout` | int | `15` | HTTP request timeout in seconds |
| `ttlSeconds` | int? | `null` (server default: 86400, 24h) | Requested grace period duration in seconds (the session token lifetime). Server clamps to `[3600, 604800]` (1h to 7d); preserved across online check-in refreshes. |
| `hwidOverride` | string? | `null` | Optional custom hardware/subject identifier. When set to a non-empty value, the SDK uses it instead of machine fingerprinting. |

### Identity-based binding example (Telegram/Discord)

```csharp
var client = new AuthForgeClient(
    appId: "YOUR_APP_ID",
    appSecret: "YOUR_APP_SECRET",
    publicKey: "YOUR_PUBLIC_KEY",
    onlineHeartbeat: true,
    hwidOverride: $"tg:{telegramUserId}" // or $"discord:{discordUserId}"
);
```

### Key rotation

To rotate the server-side signing key without a flag-day, pass the **new** and
**previous** keys via the `IEnumerable<string>` constructor; the SDK accepts a
signature matching any entry:

```csharp
var client = new AuthForgeClient(
    appId: "YOUR_APP_ID",
    appSecret: "YOUR_APP_SECRET",
    publicKeys: new[] { "NEW_PUBLIC_KEY", "PREVIOUS_PUBLIC_KEY" },
    onlineHeartbeat: true
);
```

`client.PublicKeys` exposes the full trust list; `client.PublicKey` is the first
(primary) entry. A comma-separated single string (`"NEW,PREVIOUS"`) works too.

## Grace period and online check-ins

**Grace period (default)**: after one successful online activation, the SDK keeps the app running on the Ed25519-signed session with no further network calls. A background thread re-verifies the stored signature and the expiry timestamp every `heartbeatInterval` seconds; once the session TTL expires it triggers failure with `session_expired`. The grace period is session continuation within the session TTL (default 24h, clamped by the server to 1h through 7d), not persistent offline licensing: a mid-session revocation is only picked up at the next online validate.

**Online check-ins (`onlineHeartbeat: true`)**: the SDK calls `/auth/heartbeat` every `heartbeatInterval` seconds with a fresh nonce, verifies signature + nonce, and triggers failure on invalid session state. Each successful check-in refreshes the session, so revocations and concurrent-use detection take effect on the next check-in instead of at the end of the grace period.

## Offline license files (`.authforge`)

For machines that never connect to the internet, the operator mints a **signed offline license file** in the AuthForge dashboard (License page -> *Mint .authforge file*) or via `POST /v1/licenses/{licenseKey}/offline-files`. The file is a standalone Ed25519-signed document; the SDK verifies it with **only** your app public key and the machine HWID. It never contacts AuthForge and never starts the background thread. Pass an empty `appSecret` so the air-gapped binary does not contain the App Secret.

| | Grace period (default) | Offline license file |
| --- | --- | --- |
| Needs network | Once, at `Login()` | Never on the end machine |
| What is verified | Signed *session* from `/auth/validate` | Signed *document* minted in the cloud |
| Lifetime | Session TTL: 1h to 7d | Operator-chosen expiry or lifetime (perpetual licenses only) |
| Revocation | Picked up at the next online validate / check-in | **Not** reachable: the file stays valid until its own expiry |
| Cost | 1 credit per `Login()` | 1 credit per mint; verifying is free |

```csharp
var client = new AuthForgeClient(
    appId: "YOUR_APP_ID",
    appSecret: "", // loginFromFile does not use the App Secret; do not ship it in air-gapped builds
    publicKey: "YOUR_PUBLIC_KEY",
    onFailure: (reason, ex) => Console.Error.WriteLine($"{reason}: {ex?.Message}"));

// 1. Write an activation request the operator drops into the mint dialog:
File.WriteAllText("machine.authforge-request", client.CreateActivationRequest());

// 2. Later, authorize from the minted file (path or armored text). No network.
if (client.LoginFromFile("license.authforge"))
{
    var info = client.GetOfflineLicense()!;
    Console.WriteLine($"Offline license OK until {info.ExpiresAt ?? "forever"}");
}
```

Collect the HWID from the same SDK build that will load the file: fingerprints are not portable across SDKs or languages. After `LoginFromFile()`, `GetSessionKind()` returns `SessionKind.Offline` (`SessionKind.Online` after `Login()`, `null` when logged out).

`AuthForgeClient.VerifyLicenseFile(text, appId, publicKeys, hwid)` (static) and `client.VerifyLicenseFile(pathOrText)` perform the same checks without touching client state and return a `VerifyLicenseFileResult` (`Ok`, `Error`, `License`). Failure codes, in check order: `bad_armor`, `bad_signature`, `unsupported_version`, `malformed_payload`, `wrong_app`, `expired`, `hwid_mismatch`. `LoginFromFile()` reports them through `onFailure("offline_login_failed", ex)` and returns `false`; it never calls `Environment.Exit`.

File format (version 1): PEM-style armor with informational headers, a base64 JSON payload (`v`, `appId`, `licenseKey`, `jti`, `kid`, `issuedAt`, `expiresAt`, `hwid` policy, optional label/variable snapshots) and a detached Ed25519 signature over the UTF-8 bytes of the base64 payload string - the same contract as `/auth/validate`. See `offline_license_vectors.json` for conformance vectors.

### Migrating from heartbeatMode

Earlier versions required a `string heartbeatMode` ("LOCAL" or "SERVER") as the 4th constructor parameter. The mapping:

- `heartbeatMode: "LOCAL"` maps to the default grace period behavior: just remove the argument.
- `heartbeatMode: "SERVER"` maps to `onlineHeartbeat: true`.

The old constructors still compile and behave exactly as before, but produce an obsolete warning (CS0618). The `HeartbeatMode` property is likewise obsolete; read `OnlineHeartbeat` instead.

```csharp
// Before
new AuthForgeClient(appId, appSecret, publicKey, "LOCAL");
new AuthForgeClient(appId, appSecret, publicKey, "SERVER");

// After
new AuthForgeClient(appId, appSecret, publicKey);
new AuthForgeClient(appId, appSecret, publicKey, onlineHeartbeat: true);
```

## Billing

- **One `Login()` or `ValidateLicense()` call = 1 credit** (one `/auth/validate` debit each).
- **10 online check-ins on the same session = 1 credit** (debited on every 10th successful heartbeat). The default grace period behavior makes no heartbeat calls and costs nothing after activation.

A desktop app running 6h/day with online check-ins at a 15-minute interval burns ~3-4 credits/day. `/auth/heartbeat` is limited to 6 requests/minute per license key, so keep intervals at 10 seconds or higher and choose cadence based on revocation speed needs (they always land on the **next** check-in).

## Methods

| Method | Returns | Description |
|---|---|---|
| `Login(string licenseKey)` | `bool` | Activates online and stores the signed session (`sessionToken`, `expiresIn`, `appVariables`, `licenseVariables`) |
| `ValidateLicense(string licenseKey)` | `ValidateLicenseResult` | Same `/auth/validate` + signatures as `Login`; does not update client session or start the background thread; **never** calls `onFailure` or `Environment.Exit` |
| `SelfBan(...)` | `Dictionary<string, object?>` | Requests `/auth/selfban` to blacklist HWID/IP and optionally revoke (session-authenticated only) |
| `LoginFromFile(string pathOrText)` | `bool` | Authorizes from an offline `.authforge` file with no network; never starts the background thread; failures go to `onFailure("offline_login_failed", …)` |
| `VerifyLicenseFile(string pathOrText, DateTimeOffset? now = null)` | `VerifyLicenseFileResult` | Verifies a `.authforge` file with this client's app id / keys / HWID without changing state |
| `GetOfflineLicense()` | `OfflineLicense?` | Metadata of the offline file in use (`Jti`, `ExpiresAt`, `HwidPolicy`, …) |
| `GetSessionKind()` | `SessionKind?` | `SessionKind.Online`, `SessionKind.Offline`, or `null` when logged out |
| `GetHwid()` | `string` | The HWID this client sends (or `hwidOverride`); customers share it to receive a bound file |
| `CreateActivationRequest(ActivationRequestOptions? options = null)` | `string` | Unsigned `.authforge-request` for this machine. No network, no secret. Hostname omitted unless `IncludeMachineName` |
| `Logout()` | `void` | Stops the background thread and clears all session/auth state |
| `IsAuthenticated()` | `bool` | True when an active authenticated session exists |
| `GetSessionData()` | `Dictionary<string, object?>?` | Full decoded payload map |
| `GetAppVariables()` | `Dictionary<string, object?>?` | App-scoped variables map |
| `GetLicenseVariables()` | `Dictionary<string, object?>?` | License-scoped variables map |

## Failure Handling

If authentication fails, the SDK calls your `onFailure` callback if one is provided. Without a callback, a transient background check failure (network outage, `rate_limited`, `system_error`, ...) writes a one-line warning to stderr and check-ins continue; every other failure (a rejected `Login`, a definitive check-in answer, the grace period running out) **calls `Environment.Exit(1)` to terminate the process**, so your app cannot keep running without a valid license. `Environment.Exit` does not give your code a chance to save, so set `onFailure` if your app has anything to save.

**`ValidateLicense()`** returns a result object instead; it does not invoke `onFailure` or exit for validate/network failures.

Recognized server errors:
`invalid_app`, `invalid_key`, `expired`, `revoked`, `hwid_mismatch`, `no_credits`, `app_burn_cap_reached`, `blocked`, `rate_limited`, `replay_detected`, `app_disabled`, `session_expired`, `revoke_requires_session`, `bad_request`, `malformed_request`, `demo_quota_exceeded`, `server_error`, `system_error`. Codes added to the server later are passed through unchanged.

Request retries are automatic inside the internal HTTP layer:
- `rate_limited`, or HTTP 429 with no error code: retry after 2s, then 5s (max 3 attempts total). HTTP 429 with `no_credits`, `app_burn_cap_reached` or `demo_quota_exceeded` is not retried.
- network failure: retry once after 2s
- every retry regenerates a fresh nonce

### Background check failures

Background check failures reach `onFailure("heartbeat_failed", ex)`, where `ex` is an `AuthForgeException`:

- `ex.Code`: the server's error code from the response body, whatever the HTTP status, or an SDK code: `network_error`, `timeout`, `http_error_<status>` (non-JSON error body), `invalid_json_response`, `unexpected_response`, `signature_mismatch`, `nonce_mismatch`, .... For server codes `ex.Message` equals the code; network failures keep the `url_error: ...` message.
- `ex.IsTransient` / `ex.IsFatal`: the classification. `AuthForgeClient.IsTransientError(code)` is the same check, and `AuthForgeClient.DefinitiveErrorCodes` lists the fatal codes.

| Kind | Codes | What the SDK does |
|---|---|---|
| Fatal | `revoked`, `expired`, `hwid_mismatch` (the HWID is no longer bound, for example after an HWID reset), `blocked` (HWID/IP blacklisted or not whitelisted), `session_expired` (also the grace period ending), `malformed_request`, `app_disabled`, `invalid_app`, `signature_mismatch` | Clears the stored session (as `Logout()` does) and stops background checks **before** calling `onFailure`, so `IsAuthenticated()` is `false`. `onFailure` may call `Login()` again. |
| Transient | Everything else: `network_error`, `timeout`, `rate_limited`, `system_error`, `server_error`, `no_credits`, `demo_quota_exceeded`, `app_burn_cap_reached`, `bad_request`, `invalid_key`, `http_error_<status>`, `unexpected_response`, unknown codes | Keeps the session and checks in again on the next `heartbeatInterval`. Once the signed session's TTL has passed, the next transient failure is reported as a fatal `session_expired` instead. |

`unexpected_response` means a failed check-in body was not a well-formed AuthForge verdict (`{"status":"failed","error":"<code>"}`), for example a proxy or captive portal answering instead of AuthForge; the message includes the raw `status` and `error` values.

Transient failures only keep checking in if `onFailure` returns normally. Without a callback, a transient failure prints `AuthForge: background check failed (<code>); retrying next interval` to stderr and check-ins continue; a fatal one, including the `session_expired` a transient failure becomes once the session TTL has passed, still calls `Environment.Exit(1)`. Heartbeat network failures are reported once, as `heartbeat_failed` with code `network_error` or `timeout`, not as a separate `network_error` reason.

To tolerate short outages but shut down on a definitive answer, have the callback signal your main thread and let the main thread save and exit:

```csharp
using var licenseLost = new CancellationTokenSource();

var client = new AuthForgeClient(
    appId: "YOUR_APP_ID",
    appSecret: "YOUR_APP_SECRET",
    publicKey: "YOUR_PUBLIC_KEY",
    onlineHeartbeat: true,
    ttlSeconds: 3600, // retry window for transient check-in failures
    onFailure: (reason, ex) =>
    {
        if (ex is AuthForgeException { IsTransient: true } transient)
        {
            // Connectivity problem or AuthForge overloaded: keep running. The SDK
            // checks in again every heartbeatInterval and reports session_expired
            // (fatal) once the ttlSeconds grace period is used up.
            Console.Error.WriteLine($"AuthForge check-in failed ({transient.Code}), retrying");
            return;
        }
        Console.Error.WriteLine($"License check failed: {reason} ({(ex as AuthForgeException)?.Code ?? ex?.Message})");
        // This can run on the heartbeat thread: signal the main thread instead of exiting here.
        licenseLost.Cancel();
    }
);

if (!client.Login(licenseKey))
{
    return 1;
}

while (!licenseLost.IsCancellationRequested)
{
    DoOneUnitOfWork(licenseLost.Token); // keep units short, or pass the token to async work
}

SaveUserWork();
client.Logout();
return 1;
```

In a WinForms or WPF app, marshal to the UI thread instead (`form.BeginInvoke(...)` or `Dispatcher.InvokeAsync(...)`) and close the main window normally. Calling `Environment.Exit(1)` inside `onFailure` is a last resort: `finally` blocks on other threads do not run and unsaved state is lost, so save the user's work first.

**Thread safety**: `onFailure` for `heartbeat_failed` runs on the background thread with no SDK lock held. Calling `Logout()`, `IsAuthenticated()` or `Login()` from it is safe; `Logout()` signals the thread to stop and never waits for it. A check-in response that arrives after `Logout()` or a new `Login()` is discarded, so it cannot restore the old session.

## Self-ban (tamper response)

Use `SelfBan(...)` when anti-tamper checks trigger:

```csharp
// Post-session (authenticated): defaults to revoke + HWID/IP blacklist.
client.SelfBan();

// Pre-session: pass licenseKey, SDK automatically disables revokeLicense.
client.SelfBan(licenseKey: "AF-XXXX-XXXX-XXXX");

// Custom flags:
client.SelfBan(
    blacklistHwid: true,
    blacklistIp: true,
    revokeLicense: false
);
```

`SelfBan(...)` auto-selects request mode:
- Uses post-session mode when a session token is available (`sessionToken` argument or current SDK session).
- Falls back to pre-session mode with `licenseKey` + nonce + app secret.
- In pre-session mode, revoke is forced off client-side to avoid unsafe key revocations.
- Not available after `LoginFromFile()`: offline sessions have no server session, so `SelfBan()` with no explicit `licenseKey` / `sessionToken` throws `ArgumentException("offline_session")` without contacting the server.

## How It Works

1. **Activate**: `Login` uses `hwidOverride` if provided; otherwise it collects a hardware fingerprint (MAC, CPU, disk serial). It then generates a random nonce and sends everything to the AuthForge API. The server validates the license key, binds the HWID, deducts a credit, and returns a signed payload. The SDK verifies the Ed25519 signature and nonce to prevent replay attacks.

2. **Background thread**: a background thread wakes at the configured interval. With online check-ins enabled it sends a fresh nonce to `/auth/heartbeat` and verifies the response. Otherwise it re-verifies the stored signature and checks the grace period expiry without network calls.

3. **Crypto**: both `/validate` and `/heartbeat` responses are signed by AuthForge with your app's Ed25519 private key. The SDK verifies every signed `payload` using your configured `publicKey` and rejects tampered responses.

## Test Vectors

The `test_vectors.json` file is shared across all SDKs and validates cross-language Ed25519 verification behavior. `offline_license_vectors.json` (generated from a fixed test seed in the Node SDK repo) is the cross-SDK conformance suite for `.authforge` offline license files: good files plus the `bad_signature`, wrong key, `wrong_app`, `expired`, `hwid_mismatch`, `unsupported_version` and `bad_armor` rejects.

## Requirements

- .NET 6+
- NuGet package: `BouncyCastle.Cryptography`

## License

MIT
