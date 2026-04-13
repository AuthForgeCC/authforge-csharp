# AuthForge SDK — AI Agent Reference

> This file is optimized for AI coding agents (Cursor, Copilot, Claude Code, etc.).
> It contains everything needed to correctly integrate AuthForge licensing into a project.

## What AuthForge does

AuthForge is a license key validation service. Your app sends a license key + hardware ID to the AuthForge API, gets back a cryptographically signed response, and runs background heartbeats to maintain the session. If the license is revoked or expired, the heartbeat fails and you handle it (typically exit the app).

## Installation

Copy `AuthForgeClient.cs` into your project. Targets .NET 6+; uses only BCL (`System.Net.Http`, `System.Security.Cryptography`, `System.Text.Json`).

## Minimal working integration

```csharp
using System;
using AuthForge;

void OnFailure(string reason, Exception? exception)
{
    Console.Error.WriteLine($"AuthForge: {reason}");
    if (exception != null)
        Console.Error.WriteLine(exception);
    Environment.Exit(1);
}

var client = new AuthForgeClient(
    appId: "YOUR_APP_ID",
    appSecret: "YOUR_APP_SECRET",
    heartbeatMode: "SERVER",
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
// --- Your application code ends here ---

client.Logout();
```

## Constructor parameters

| Parameter | Type | Required | Default | Description |
|-----------|------|----------|---------|-------------|
| `appId` | `string` | yes | — | Application ID |
| `appSecret` | `string` | yes | — | Application secret |
| `heartbeatMode` | `string` | yes | — | `"SERVER"` or `"LOCAL"` (case-insensitive) |
| `heartbeatInterval` | `int` | no | `900` | Seconds between heartbeats |
| `apiBaseUrl` | `string` | no | `https://auth.authforge.cc` | API base URL |
| `onFailure` | `Action<string, Exception?>?` | no | `null` | Called on failure; if null, `Environment.Exit(1)` |
| `requestTimeout` | `int` | no | `15` | HTTP timeout (seconds) |

## Methods

| Method | Returns | Description |
|--------|---------|-------------|
| `Login(string licenseKey)` | `bool` | Validates license, verifies signatures, starts heartbeat thread |
| `Logout()` | `void` | Stops heartbeat and clears session state |
| `IsAuthenticated()` | `bool` | Whether a session exists |
| `GetSessionData()` | `Dictionary<string, object?>?` | Decoded payload map |
| `GetAppVariables()` | `Dictionary<string, object?>?` | App-scoped variables |
| `GetLicenseVariables()` | `Dictionary<string, object?>?` | License-scoped variables |

## Error codes the server can return

invalid_app, invalid_key, expired, revoked, hwid_mismatch, no_credits, blocked, rate_limited, replay_detected, session_expired, app_disabled, bad_request

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

### Custom error handling

Failed validation often surfaces as `ArgumentException` whose message is the server error code (e.g. `invalid_key`). Reasons passed to `onFailure` include `login_failed` and `heartbeat_failed`.

```csharp
onFailure: (reason, ex) =>
{
    if (ex is ArgumentException ae && ae.Message is "invalid_key" or "expired" or "revoked")
        Console.Error.WriteLine($"License: {ae.Message}");
    Environment.Exit(1);
}
```

## Do NOT

- Do not hardcode the app secret as a plain string literal in source — use environment variables or encrypted config
- Do not skip `onFailure` — without it, failures call `Environment.Exit(1)` without your cleanup
- Do not call `Login` on every app action — call once at startup; heartbeats handle the rest
- Do not use `heartbeatMode: "LOCAL"` unless the app has no internet after initial auth
