# AuthForge C# SDK

Official C# SDK for [AuthForge](https://authforge.cc) — credit-based license key authentication with HMAC-verified heartbeats.

**Zero external dependencies.** Standard library only (`System.Net.Http`, `System.Security.Cryptography`, `System.Text.Json`). Targets .NET 6+.

## Quick Start

Copy `AuthForgeClient.cs` into your project, then:

```csharp
using AuthForge;

var client = new AuthForgeClient(
    appId: "YOUR_APP_ID",           // from your AuthForge dashboard
    appSecret: "YOUR_APP_SECRET",   // from your AuthForge dashboard
    heartbeatMode: "SERVER"         // "SERVER" or "LOCAL"
);

Console.Write("Enter license key: ");
var key = Console.ReadLine() ?? "";

if (client.Login(key))
{
    Console.WriteLine("Authenticated!");
    // Your app logic here — heartbeats run automatically in the background
}
else
{
    Console.WriteLine("Invalid license key.");
    Environment.Exit(1);
}
```

## Configuration

| Parameter | Type | Default | Description |
|---|---|---|---|
| `appId` | string | required | Your application ID from the AuthForge dashboard |
| `appSecret` | string | required | Your application secret from the AuthForge dashboard |
| `heartbeatMode` | string | required | `"SERVER"` or `"LOCAL"` (see below) |
| `heartbeatInterval` | int | `900` | Seconds between heartbeat checks (default 15 min) |
| `apiBaseUrl` | string | `https://auth.authforge.cc` | API endpoint |
| `onFailure` | Action\<string, Exception?\> | `null` | Callback on auth failure |
| `requestTimeout` | int | `15` | HTTP request timeout in seconds |

## Methods

| Method | Returns | Description |
|---|---|---|
| `Login(string licenseKey)` | `bool` | Validates key and stores signed session (`sessionToken`, `expiresIn`, `appVariables`, `licenseVariables`) |
| `Logout()` | `void` | Stops heartbeat and clears all session/auth state |
| `IsAuthenticated()` | `bool` | True when an active authenticated session exists |
| `GetSessionData()` | `Dictionary<string, object?>?` | Full decoded payload map |
| `GetAppVariables()` | `Dictionary<string, object?>?` | App-scoped variables map |
| `GetLicenseVariables()` | `Dictionary<string, object?>?` | License-scoped variables map |

## Heartbeat Modes

**SERVER** — The SDK calls `/auth/heartbeat` every `heartbeatInterval` seconds with a fresh nonce, verifies signature + nonce, and triggers failure on invalid session state.

**LOCAL** — No network calls. The SDK re-verifies stored signature state and checks expiry timestamp locally. If expired, it triggers failure with `session_expired`.

## Failure Handling

If authentication fails, the SDK calls your `onFailure` callback if one is provided. If no callback is set, **the SDK calls `Environment.Exit(1)` to terminate the process.** This is intentional — it prevents your app from running without a valid license.

Recognized server errors:
`invalid_app`, `invalid_key`, `expired`, `revoked`, `hwid_mismatch`, `no_credits`, `blocked`, `rate_limited`, `replay_detected`, `app_disabled`, `session_expired`, `bad_request`, `checksum_required`, `checksum_mismatch`

Request retries are automatic inside the internal HTTP layer:
- `rate_limited`: retry after 2s, then 5s (max 3 attempts total)
- network failure: retry once after 2s
- every retry regenerates a fresh nonce

```csharp
var client = new AuthForgeClient(
    appId: "YOUR_APP_ID",
    appSecret: "YOUR_APP_SECRET",
    heartbeatMode: "SERVER",
    onFailure: (reason, exception) =>
    {
        Console.WriteLine($"Auth failed: {reason}");
        if (exception != null)
            Console.WriteLine($"Details: {exception.Message}");
        Environment.Exit(1);
    }
);
```

## How It Works

1. **Login** — Collects a hardware fingerprint (MAC, CPU, disk serial), generates a random nonce, and sends everything to the AuthForge API. The server validates the license key, binds the HWID, deducts a credit, and returns a signed payload. The SDK verifies the HMAC-SHA256 signature and nonce to prevent replay attacks.

2. **Heartbeat** — A background thread checks in at the configured interval. In SERVER mode, it sends a fresh nonce and verifies the response. In LOCAL mode, it re-verifies the stored signature and checks expiry without network calls.

3. **Crypto** — Every response is signed with a key derived from `SHA256(appSecret + nonce)`. The signing key changes on every call, making replay and MITM attacks impractical.

## Test Vectors

The `GenerateVectors.cs` script and `test_vectors.json` file are provided for cross-SDK verification. This SDK produces identical cryptographic outputs to the Python and C++ reference implementations.

## Requirements

- .NET 6+
- No NuGet packages

## License

MIT
