# AuthForge C# SDK

Official C# SDK for [AuthForge](https://authforge.cc) — credit-based license key authentication with Ed25519-verified responses.

Dependencies: `BouncyCastle.Cryptography` for Ed25519 verification. Targets .NET 6+.

## Installation

The package is **`AuthForge`** on [NuGet](https://www.nuget.org/packages/AuthForge/).

```bash
dotnet add package AuthForge
```

**Alternative:** copy `AuthForgeClient.cs` into your solution if you need a source-only vendored layout (you still need the same NuGet dependencies declared in your project).

## Quick Start

```csharp
using AuthForge;

var client = new AuthForgeClient(
    appId: "YOUR_APP_ID",           // from your AuthForge dashboard
    appSecret: "YOUR_APP_SECRET",   // from your AuthForge dashboard
    publicKey: "YOUR_PUBLIC_KEY",   // base64 Ed25519 public key from dashboard
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
| `publicKey` | string | required | App Ed25519 public key (base64) from dashboard |
| `heartbeatMode` | string | required | `"SERVER"` or `"LOCAL"` (see below) |
| `heartbeatInterval` | int | `900` | Seconds between heartbeat checks (any value ≥ 1; default 15 min) |
| `apiBaseUrl` | string | `https://auth.authforge.cc` | API endpoint |
| `onFailure` | Action\<string, Exception?\> | `null` | Callback on auth failure |
| `requestTimeout` | int | `15` | HTTP request timeout in seconds |
| `ttlSeconds` | int? | `null` (server default: 86400) | Requested session token lifetime. Server clamps to `[3600, 604800]`; preserved across heartbeat refreshes. |

## Billing

- **One `Login()` call = 1 credit** (one `/auth/validate` debit).
- **10 heartbeats on the same session = 1 credit** (debited on every 10th successful heartbeat).

Any heartbeat interval is safe economically: a desktop app running 6h/day at a 15-minute interval burns ~3–4 credits/day; a server app running 24/7 at a 1-minute interval burns ~145 credits/day. Choose your interval based on how quickly you need revocations to propagate (they always land on the **next** heartbeat).

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
`invalid_app`, `invalid_key`, `expired`, `revoked`, `hwid_mismatch`, `no_credits`, `blocked`, `rate_limited`, `replay_detected`, `app_disabled`, `session_expired`, `bad_request`

Request retries are automatic inside the internal HTTP layer:
- `rate_limited`: retry after 2s, then 5s (max 3 attempts total)
- network failure: retry once after 2s
- every retry regenerates a fresh nonce

```csharp
var client = new AuthForgeClient(
    appId: "YOUR_APP_ID",
    appSecret: "YOUR_APP_SECRET",
    publicKey: "YOUR_PUBLIC_KEY",
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

1. **Login** — Collects a hardware fingerprint (MAC, CPU, disk serial), generates a random nonce, and sends everything to the AuthForge API. The server validates the license key, binds the HWID, deducts a credit, and returns a signed payload. The SDK verifies the Ed25519 signature and nonce to prevent replay attacks.

2. **Heartbeat** — A background thread checks in at the configured interval. In SERVER mode, it sends a fresh nonce and verifies the response. In LOCAL mode, it re-verifies the stored signature and checks expiry without network calls.

3. **Crypto** — Both `/validate` and `/heartbeat` responses are signed by AuthForge with your app's Ed25519 private key. The SDK verifies every signed `payload` using your configured `publicKey` and rejects tampered responses.

## Test Vectors

The `test_vectors.json` file is shared across all SDKs and validates cross-language Ed25519 verification behavior.

## Requirements

- .NET 6+
- NuGet package: `BouncyCastle.Cryptography`

## License

MIT
