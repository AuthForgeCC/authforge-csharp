using System.IO;
using System.Net;
using System.Net.Sockets;
using System.Reflection;
using System.Text;
using System.Text.Json;
using Xunit;

namespace AuthForge.Tests;

[Collection(TestNonceCollection.Name)]
public class HeartbeatTests
{
    private const string TestPublicKey = "0wRcYWn44wk9tHOisXgso1wbtUqpFdy0IeMk4HXDiNc=";
    private const string HeartbeatNonce = "nonce-heartbeat-001";
    private static readonly BindingFlags InstanceNonPublic = BindingFlags.Instance | BindingFlags.NonPublic;
    private static readonly TimeSpan DeadlockTimeout = TimeSpan.FromSeconds(10);

    public static IEnumerable<object[]> DefinitiveCases()
    {
        var cases = new (string Code, int Status)[]
        {
            ("revoked", 410),
            ("expired", 410),
            ("hwid_mismatch", 403),
            ("blocked", 403),
            ("app_disabled", 403),
            ("session_expired", 401),
            ("invalid_app", 401),
            ("malformed_request", 400),
        };
        foreach (var (code, status) in cases)
        {
            yield return new object[] { code, status };
            yield return new object[] { code, 200 };
        }
    }

    [Theory]
    [MemberData(nameof(DefinitiveCases))]
    public void DefinitiveServerCode_ClearsSessionAndStops(string code, int httpStatus)
    {
        using var server = ScriptedServer.Respond((httpStatus, FailedBody(code)));
        using var harness = new Harness(server.BaseUrl);
        harness.SeedOnlineSession();

        Assert.False(harness.Client.HeartbeatTick());

        var failure = harness.SingleFailure();
        Assert.Equal(code, failure.Code);
        Assert.Equal(code, failure.Message);
        Assert.True(failure.IsFatal);
        Assert.False(harness.Client.IsAuthenticated());
        Assert.Null(harness.Client.GetSessionKind());
        Assert.Equal(1, server.RequestCount);
        Assert.Empty(harness.Sleeps);
    }

    [Fact]
    public void TamperedSuccessResponse_IsSignatureMismatch()
    {
        var heartbeat = Vectors.Case("heartbeat_success");
        var tampered = Vectors.Case("tampered_payload");
        using var server = ScriptedServer.Respond((200, SuccessBody(heartbeat.Payload, tampered.Signature)));
        using var harness = new Harness(server.BaseUrl);
        harness.SeedOnlineSession();

        AuthForgeClient.TestNonceOverride = HeartbeatNonce;
        try
        {
            Assert.False(harness.Client.HeartbeatTick());
        }
        finally
        {
            AuthForgeClient.TestNonceOverride = null;
        }

        var failure = harness.SingleFailure();
        Assert.Equal("signature_mismatch", failure.Code);
        Assert.Equal("signature_mismatch", failure.Message);
        Assert.True(failure.IsFatal);
        Assert.False(harness.Client.IsAuthenticated());
    }

    [Theory]
    [InlineData("rate_limited", 429, 3)]
    [InlineData("system_error", 500, 1)]
    [InlineData("server_error", 500, 1)]
    [InlineData("no_credits", 429, 1)]
    [InlineData("demo_quota_exceeded", 429, 1)]
    [InlineData("app_burn_cap_reached", 429, 1)]
    [InlineData("bad_request", 400, 1)]
    [InlineData("invalid_key", 400, 1)]
    [InlineData("brand_new_code", 400, 1)]
    public void TransientServerCode_KeepsSessionAndContinues(string code, int httpStatus, int expectedRequests)
    {
        using var server = ScriptedServer.Respond((httpStatus, FailedBody(code)));
        using var harness = new Harness(server.BaseUrl);
        harness.SeedOnlineSession();

        Assert.True(harness.Client.HeartbeatTick());

        var failure = harness.SingleFailure();
        Assert.Equal(code, failure.Code);
        Assert.Equal(code, failure.Message);
        Assert.True(failure.IsTransient);
        Assert.True(harness.Client.IsAuthenticated());
        Assert.Equal(expectedRequests, server.RequestCount);
        var expectedSleeps = expectedRequests == 3
            ? new[] { TimeSpan.FromSeconds(2), TimeSpan.FromSeconds(5) }
            : Array.Empty<TimeSpan>();
        Assert.Equal(expectedSleeps, harness.Sleeps);
    }

    [Theory]
    [InlineData(403, "Forbidden", "http_error_403")]
    [InlineData(500, "<html>Internal Server Error</html>", "http_error_500")]
    [InlineData(502, "Bad Gateway", "http_error_502")]
    [InlineData(500, "", "http_error_500")]
    [InlineData(200, "", "invalid_json_response")]
    [InlineData(200, "[1,2,3]", "response_not_json_object")]
    [InlineData(200, "\"ok\"", "response_not_json_object")]
    public void UnparseableResponse_IsTransient(int httpStatus, string body, string expectedCode)
    {
        using var server = ScriptedServer.Respond((httpStatus, body));
        using var harness = new Harness(server.BaseUrl);
        harness.SeedOnlineSession();

        Assert.True(harness.Client.HeartbeatTick());

        var failure = harness.SingleFailure();
        Assert.Equal(expectedCode, failure.Code);
        Assert.True(failure.IsTransient);
        Assert.True(harness.Client.IsAuthenticated());
        Assert.Equal(1, server.RequestCount);
    }

    [Theory]
    [InlineData(403, "{\"error\":\"revoked\"}", "\"revoked\"")]
    [InlineData(410, "{\"status\":\"revoked\"}", "\"revoked\"")]
    [InlineData(401, "{\"status\":\"failed\"}", "<missing>")]
    [InlineData(200, "{\"status\":\"failed\",\"error\":\"\"}", "\"\"")]
    [InlineData(403, "{\"status\":\"failed\",\"error\":403}", "403")]
    public void MalformedFailureBody_IsUnexpectedResponse(int httpStatus, string body, string expectedFragment)
    {
        using var server = ScriptedServer.Respond((httpStatus, body));
        using var harness = new Harness(server.BaseUrl);
        harness.SeedOnlineSession();

        Assert.True(harness.Client.HeartbeatTick());

        var failure = harness.SingleFailure();
        Assert.Equal("unexpected_response", failure.Code);
        Assert.StartsWith("unexpected_response", failure.Message);
        Assert.Contains(expectedFragment, failure.Message);
        Assert.True(failure.IsTransient);
        Assert.True(harness.Client.IsAuthenticated());
    }

    [Fact]
    public void WellFormedFailureBody_AcceptsCaseAndWhitespaceInStatus()
    {
        using var server = ScriptedServer.Respond((410, "{\"status\":\" FAILED \",\"error\":\"Revoked\"}"));
        using var harness = new Harness(server.BaseUrl);
        harness.SeedOnlineSession();

        Assert.False(harness.Client.HeartbeatTick());
        Assert.Equal("revoked", harness.SingleFailure().Code);
    }

    [Fact]
    public void NetworkError_IsTransientAndReportedOnce()
    {
        using var harness = new Harness($"http://127.0.0.1:{GetFreeTcpPort()}");
        harness.SeedOnlineSession();

        Assert.True(harness.Client.HeartbeatTick());

        var (reason, error) = Assert.Single(harness.Failures);
        Assert.Equal("heartbeat_failed", reason);
        var failure = Assert.IsType<AuthForgeException>(error);
        Assert.Equal("network_error", failure.Code);
        Assert.StartsWith("url_error:", failure.Message);
        Assert.IsType<HttpRequestException>(failure.InnerException);
        Assert.True(failure.IsTransient);
        Assert.True(harness.Client.IsAuthenticated());
        Assert.Equal(new[] { TimeSpan.FromSeconds(2) }, harness.Sleeps);
    }

    [Fact]
    public void Timeout_IsTransientAndReportedOnce()
    {
        using var server = ScriptedServer.Hanging();
        using var harness = new Harness(server.BaseUrl, requestTimeout: 1);
        harness.SeedOnlineSession();

        Assert.True(harness.Client.HeartbeatTick());

        var (reason, error) = Assert.Single(harness.Failures);
        Assert.Equal("heartbeat_failed", reason);
        var failure = Assert.IsType<AuthForgeException>(error);
        Assert.Equal("timeout", failure.Code);
        Assert.StartsWith("url_error:", failure.Message);
        Assert.True(failure.IsTransient);
        Assert.True(harness.Client.IsAuthenticated());
        Assert.Equal(2, server.RequestCount);
        Assert.Equal(new[] { TimeSpan.FromSeconds(2) }, harness.Sleeps);
    }

    [Fact]
    public void TransientFailureAfterSessionTtl_IsPromotedToSessionExpired()
    {
        using var server = ScriptedServer.Respond((500, FailedBody("system_error")));
        using var harness = new Harness(server.BaseUrl);
        harness.SeedOnlineSession(expiresIn: DateTimeOffset.UtcNow.ToUnixTimeSeconds() - 60);

        Assert.False(harness.Client.HeartbeatTick());

        var failure = harness.SingleFailure();
        Assert.Equal("session_expired", failure.Code);
        Assert.Equal("session_expired", failure.Message);
        Assert.True(failure.IsFatal);
        var inner = Assert.IsType<AuthForgeException>(failure.InnerException);
        Assert.Equal("system_error", inner.Code);
        Assert.False(harness.Client.IsAuthenticated());
    }

    [Fact]
    public void WithoutOnFailure_TransientFailure_WarnsAndContinues()
    {
        using var server = ScriptedServer.Respond((503, FailedBody("system_error")));
        using var harness = new Harness(server.BaseUrl, withOnFailure: false);
        harness.SeedOnlineSession();

        Assert.True(harness.Client.HeartbeatTick());

        Assert.Empty(harness.Exits);
        Assert.Equal(
            new[] { "AuthForge: background check failed (system_error); retrying next interval" },
            harness.Warnings);
        Assert.True(harness.Client.IsAuthenticated());
    }

    [Theory]
    [InlineData(410, "revoked", 3600)]
    [InlineData(503, "system_error", -60)]
    public void WithoutOnFailure_DefinitiveFailure_Exits(int httpStatus, string code, int expiresInOffset)
    {
        using var server = ScriptedServer.Respond((httpStatus, FailedBody(code)));
        using var harness = new Harness(server.BaseUrl, withOnFailure: false);
        harness.SeedOnlineSession(expiresIn: DateTimeOffset.UtcNow.ToUnixTimeSeconds() + expiresInOffset);

        Assert.False(harness.Client.HeartbeatTick());

        Assert.Equal(new[] { 1 }, harness.Exits);
        Assert.Empty(harness.Warnings);
        Assert.False(harness.Client.IsAuthenticated());
    }

    [Fact]
    public void WithoutOnFailure_LoginFailure_Exits()
    {
        using var server = ScriptedServer.Respond((401, FailedBody("invalid_key")));
        using var harness = new Harness(server.BaseUrl, withOnFailure: false);

        Assert.False(harness.Client.Login("license-key"));

        Assert.Equal(new[] { 1 }, harness.Exits);
        Assert.Empty(harness.Warnings);
    }

    [Fact]
    public void SuccessAfterTransientFailure_RefreshesSession()
    {
        var heartbeat = Vectors.Case("heartbeat_success");
        using var server = ScriptedServer.Respond(
            (500, FailedBody("system_error")),
            (200, SuccessBody(heartbeat.Payload, heartbeat.Signature)));
        using var harness = new Harness(server.BaseUrl);
        harness.SeedOnlineSession();

        AuthForgeClient.TestNonceOverride = HeartbeatNonce;
        try
        {
            Assert.True(harness.Client.HeartbeatTick());
            Assert.True(harness.Client.HeartbeatTick());
        }
        finally
        {
            AuthForgeClient.TestNonceOverride = null;
        }

        Assert.Equal("system_error", harness.SingleFailure().Code);
        Assert.True(harness.Client.IsAuthenticated());
        Assert.Equal("session.heartbeat.token", GetField(harness.Client, "_sessionToken"));
        Assert.Equal(1900000300L, GetField(harness.Client, "_sessionExpiresIn"));
        Assert.Equal(2, server.RequestCount);
    }

    [Fact]
    public void GracePeriodExpiry_IsSessionExpiredAndClearsSession()
    {
        var validate = Vectors.Case("validate_success");
        using var harness = new Harness("http://127.0.0.1", onlineHeartbeat: false);
        harness.SeedOnlineSession(
            expiresIn: DateTimeOffset.UtcNow.ToUnixTimeSeconds() - 1,
            payload: validate.Payload,
            signature: validate.Signature);

        Assert.False(harness.Client.HeartbeatTick());

        var failure = harness.SingleFailure();
        Assert.Equal("session_expired", failure.Code);
        Assert.Equal("session_expired", failure.Message);
        Assert.True(failure.IsFatal);
        Assert.False(harness.Client.IsAuthenticated());
    }

    [Fact]
    public void GracePeriodWithinTtl_KeepsSession()
    {
        var validate = Vectors.Case("validate_success");
        using var harness = new Harness("http://127.0.0.1", onlineHeartbeat: false);
        harness.SeedOnlineSession(payload: validate.Payload, signature: validate.Signature);

        Assert.True(harness.Client.HeartbeatTick());

        Assert.Empty(harness.Failures);
        Assert.True(harness.Client.IsAuthenticated());
    }

    [Fact]
    public void GracePeriodWithTamperedSignature_IsSignatureMismatch()
    {
        var validate = Vectors.Case("validate_success");
        var wrongKey = Vectors.Case("wrong_app_key");
        using var harness = new Harness("http://127.0.0.1", onlineHeartbeat: false);
        harness.SeedOnlineSession(payload: validate.Payload, signature: wrongKey.Signature);

        Assert.False(harness.Client.HeartbeatTick());

        Assert.Equal("signature_mismatch", harness.SingleFailure().Code);
        Assert.False(harness.Client.IsAuthenticated());
    }

    [Theory]
    [InlineData("revoked", false)]
    [InlineData("expired", false)]
    [InlineData("hwid_mismatch", false)]
    [InlineData("blocked", false)]
    [InlineData("session_expired", false)]
    [InlineData("malformed_request", false)]
    [InlineData("app_disabled", false)]
    [InlineData("invalid_app", false)]
    [InlineData("signature_mismatch", false)]
    [InlineData("rate_limited", true)]
    [InlineData("system_error", true)]
    [InlineData("server_error", true)]
    [InlineData("no_credits", true)]
    [InlineData("demo_quota_exceeded", true)]
    [InlineData("app_burn_cap_reached", true)]
    [InlineData("bad_request", true)]
    [InlineData("invalid_key", true)]
    [InlineData("replay_detected", true)]
    [InlineData("revoke_requires_session", true)]
    [InlineData("network_error", true)]
    [InlineData("timeout", true)]
    [InlineData("http_error_403", true)]
    [InlineData("http_error_500", true)]
    [InlineData("invalid_json_response", true)]
    [InlineData("response_not_json_object", true)]
    [InlineData("unexpected_response", true)]
    [InlineData("missing_session_token", true)]
    [InlineData("nonce_mismatch", true)]
    [InlineData("unknown_error", true)]
    [InlineData("brand_new_code", true)]
    [InlineData("REVOKED", true)]
    [InlineData(null, true)]
    public void IsTransientError_UsesDefinitiveAllowlist(string? code, bool expected)
    {
        Assert.Equal(expected, AuthForgeClient.IsTransientError(code));
        if (code is not null)
        {
            var exception = new AuthForgeException(code);
            Assert.Equal(expected, exception.IsTransient);
            Assert.Equal(!expected, exception.IsFatal);
            Assert.Equal(code, exception.Message);
        }
    }

    [Fact]
    public void DefinitiveErrorCodes_IsTheAllowlist()
    {
        Assert.Equal(
            new[] { "app_disabled", "blocked", "expired", "hwid_mismatch", "invalid_app", "malformed_request", "revoked", "session_expired", "signature_mismatch" },
            AuthForgeClient.DefinitiveErrorCodes.OrderBy(c => c, StringComparer.Ordinal));
    }

    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public async Task OnFailure_CanCallLogoutAndIsAuthenticated_WithoutDeadlock(bool fatal)
    {
        using var server = fatal
            ? ScriptedServer.Respond((410, FailedBody("revoked")))
            : ScriptedServer.Respond((500, FailedBody("system_error")));
        bool? authenticatedInCallback = null;
        using var harness = new Harness(server.BaseUrl, onFailure: (client, _, _) =>
        {
            authenticatedInCallback = client.IsAuthenticated();
            client.Logout();
            _ = client.IsAuthenticated();
        });
        harness.SeedOnlineSession();

        var tick = Task.Run(() => harness.Client.HeartbeatTick());
        var completed = await Task.WhenAny(tick, Task.Delay(DeadlockTimeout));
        Assert.True(completed == tick, "HeartbeatTick deadlocked");

        Assert.Equal(!fatal, await tick);
        Assert.Equal(!fatal, authenticatedInCallback);
        Assert.False(harness.Client.IsAuthenticated());
        Assert.Single(harness.Failures);
    }

    [Fact]
    public void LogoutDuringInFlightHeartbeat_LeavesClientLoggedOut()
    {
        var heartbeat = Vectors.Case("heartbeat_success");
        using var server = ScriptedServer.Respond((200, SuccessBody(heartbeat.Payload, heartbeat.Signature)));
        using var harness = new Harness(server.BaseUrl);
        harness.SeedOnlineSession();
        server.BeforeRespond = _ => harness.Client.Logout();

        AuthForgeClient.TestNonceOverride = HeartbeatNonce;
        try
        {
            harness.Client.HeartbeatTick();
        }
        finally
        {
            AuthForgeClient.TestNonceOverride = null;
        }

        Assert.Equal(1, server.RequestCount);
        Assert.False(harness.Client.IsAuthenticated());
        Assert.Null(GetField(harness.Client, "_sessionToken"));
        Assert.Null(harness.Client.GetSessionData());
        Assert.Empty(harness.Failures);
    }

    [Fact]
    public void LogoutDuringInFlightFailure_DoesNotReport()
    {
        using var server = ScriptedServer.Respond((410, FailedBody("revoked")));
        using var harness = new Harness(server.BaseUrl);
        harness.SeedOnlineSession();
        server.BeforeRespond = _ => harness.Client.Logout();

        Assert.False(harness.Client.HeartbeatTick());

        Assert.Empty(harness.Failures);
        Assert.False(harness.Client.IsAuthenticated());
    }

    [Fact]
    public void HeartbeatTick_WithoutOnlineSession_DoesNothing()
    {
        using var server = ScriptedServer.Respond((200, "{}"));
        using var harness = new Harness(server.BaseUrl);

        Assert.False(harness.Client.HeartbeatTick());

        Assert.Equal(0, server.RequestCount);
        Assert.Empty(harness.Failures);
    }

    [Fact]
    public void Logout_StopsHeartbeatThreadPromptly()
    {
        using var harness = new Harness("http://127.0.0.1");
        harness.SeedOnlineSession();
        typeof(AuthForgeClient).GetMethod("StartHeartbeatOnce", InstanceNonPublic)!.Invoke(harness.Client, null);
        var thread = Assert.IsType<Thread>(GetField(harness.Client, "_heartbeatThread"));

        harness.Client.Logout();

        Assert.True(thread.Join(TimeSpan.FromSeconds(5)), "heartbeat thread did not stop after Logout");
        Assert.Empty(harness.Failures);
    }

    [Fact]
    public void ValidateLicense_DoesNotRetryNoCredits429()
    {
        using var server = ScriptedServer.Respond((429, FailedBody("no_credits")));
        using var harness = new Harness(server.BaseUrl);

        var result = harness.Client.ValidateLicense("license-key");

        Assert.False(result.Valid);
        Assert.Equal("no_credits", result.ErrorCode);
        Assert.Equal(1, server.RequestCount);
        Assert.Empty(harness.Sleeps);
    }

    [Fact]
    public void ValidateLicense_Retries429WithoutErrorCode()
    {
        using var server = ScriptedServer.Respond((429, "{}"));
        using var harness = new Harness(server.BaseUrl);

        var result = harness.Client.ValidateLicense("license-key");

        Assert.False(result.Valid);
        Assert.Equal("unknown_error", result.ErrorCode);
        Assert.Equal(3, server.RequestCount);
        Assert.Equal(new[] { TimeSpan.FromSeconds(2), TimeSpan.FromSeconds(5) }, harness.Sleeps);
    }

    [Fact]
    public void ValidateLicense_PassesThroughUnknownServerCode()
    {
        using var server = ScriptedServer.Respond((400, FailedBody("brand_new_code")));
        using var harness = new Harness(server.BaseUrl);

        var result = harness.Client.ValidateLicense("license-key");

        Assert.Equal("brand_new_code", result.ErrorCode);
    }

    [Fact]
    public void ValidateLicense_NetworkError_KeepsUrlErrorMessage()
    {
        using var harness = new Harness($"http://127.0.0.1:{GetFreeTcpPort()}");

        var result = harness.Client.ValidateLicense("license-key");

        Assert.False(result.Valid);
        Assert.StartsWith("url_error:", result.ErrorCode);
        var error = Assert.IsType<AuthForgeException>(result.Error);
        Assert.Equal("network_error", error.Code);
        Assert.Empty(harness.Failures);
    }

    private static string FailedBody(string code)
    {
        return JsonSerializer.Serialize(new Dictionary<string, object?> { ["status"] = "failed", ["error"] = code });
    }

    private static string SuccessBody(string payload, string signature)
    {
        return JsonSerializer.Serialize(new Dictionary<string, object?>
        {
            ["status"] = "ok",
            ["payload"] = payload,
            ["signature"] = signature,
            ["keyId"] = "signing-key-1",
        });
    }

    private static object? GetField(AuthForgeClient client, string name)
    {
        var field = typeof(AuthForgeClient).GetField(name, InstanceNonPublic);
        Assert.NotNull(field);
        return field!.GetValue(client);
    }

    private static void SetField(AuthForgeClient client, string name, object? value)
    {
        var field = typeof(AuthForgeClient).GetField(name, InstanceNonPublic);
        Assert.NotNull(field);
        field!.SetValue(client, value);
    }

    private static int GetFreeTcpPort()
    {
        var l = new TcpListener(IPAddress.Loopback, 0);
        l.Start();
        var port = ((IPEndPoint)l.LocalEndpoint).Port;
        l.Stop();
        return port;
    }

    private static class Vectors
    {
        private static readonly Lazy<JsonDocument> Document = new(() =>
            JsonDocument.Parse(File.ReadAllText(Path.Combine(AppContext.BaseDirectory, "test_vectors.json"))));

        public static (string Payload, string Signature) Case(string id)
        {
            var entry = Document.Value.RootElement.GetProperty("cases").EnumerateArray()
                .First(e => e.GetProperty("id").GetString() == id);
            return (entry.GetProperty("payload").GetString()!, entry.GetProperty("signature").GetString()!);
        }
    }

    private sealed class Harness : IDisposable
    {
        private readonly object _gate = new();
        private readonly List<(string Reason, Exception? Error)> _failures = new();
        private readonly List<TimeSpan> _sleeps = new();
        private readonly List<int> _exits = new();
        private readonly List<string> _warnings = new();

        public Harness(
            string baseUrl,
            bool onlineHeartbeat = true,
            int requestTimeout = 5,
            Action<AuthForgeClient, string, Exception?>? onFailure = null,
            bool withOnFailure = true)
        {
            Client = new AuthForgeClient(
                "app-id",
                "app-secret",
                TestPublicKey,
                onlineHeartbeat: onlineHeartbeat,
                heartbeatInterval: 3600,
                apiBaseUrl: baseUrl,
                onFailure: withOnFailure
                    ? (reason, ex) =>
                    {
                        lock (_gate)
                        {
                            _failures.Add((reason, ex));
                        }
                        onFailure?.Invoke(Client!, reason, ex);
                    }
                    : null,
                requestTimeout: requestTimeout,
                hwidOverride: "test-hwid");
            Client.SleepFn = delay =>
            {
                lock (_gate)
                {
                    _sleeps.Add(delay);
                }
            };
            Client.ExitFn = code =>
            {
                lock (_gate)
                {
                    _exits.Add(code);
                }
            };
            Client.WarnFn = message =>
            {
                lock (_gate)
                {
                    _warnings.Add(message);
                }
            };
        }

        public IReadOnlyList<int> Exits
        {
            get
            {
                lock (_gate)
                {
                    return _exits.ToList();
                }
            }
        }

        public IReadOnlyList<string> Warnings
        {
            get
            {
                lock (_gate)
                {
                    return _warnings.ToList();
                }
            }
        }

        public AuthForgeClient Client { get; }

        public IReadOnlyList<(string Reason, Exception? Error)> Failures
        {
            get
            {
                lock (_gate)
                {
                    return _failures.ToList();
                }
            }
        }

        public IReadOnlyList<TimeSpan> Sleeps
        {
            get
            {
                lock (_gate)
                {
                    return _sleeps.ToList();
                }
            }
        }

        public AuthForgeException SingleFailure()
        {
            var (reason, error) = Assert.Single(Failures);
            Assert.Equal("heartbeat_failed", reason);
            return Assert.IsType<AuthForgeException>(error);
        }

        public void SeedOnlineSession(long? expiresIn = null, string? payload = null, string? signature = null)
        {
            SetField(Client, "_licenseKey", "license-key");
            SetField(Client, "_sessionToken", "session.seed.token");
            SetField(Client, "_sessionExpiresIn", expiresIn ?? DateTimeOffset.UtcNow.ToUnixTimeSeconds() + 3600);
            SetField(Client, "_rawPayloadB64", payload);
            SetField(Client, "_signature", signature);
            SetField(Client, "_authenticated", true);
            SetField(Client, "_sessionKind", SessionKind.Online);
        }

        public void Dispose()
        {
            Client.Logout();
        }
    }

    private sealed class ScriptedServer : IDisposable
    {
        private readonly HttpListener _listener = new();
        private readonly (int Status, string Body)[] _script;
        private readonly bool _hang;
        private readonly List<HttpListenerContext> _hungContexts = new();
        private readonly Thread _thread;
        private int _requestCount;

        private ScriptedServer((int Status, string Body)[] script, bool hang)
        {
            _script = script;
            _hang = hang;
            var port = GetFreeTcpPort();
            BaseUrl = $"http://127.0.0.1:{port}";
            _listener.Prefixes.Add(BaseUrl + "/");
            _listener.Start();
            _thread = new Thread(Serve) { IsBackground = true };
            _thread.Start();
        }

        public static ScriptedServer Respond(params (int Status, string Body)[] script) => new(script, hang: false);

        public static ScriptedServer Hanging() => new(Array.Empty<(int, string)>(), hang: true);

        public string BaseUrl { get; }

        public int RequestCount => Volatile.Read(ref _requestCount);

        public Action<int>? BeforeRespond { get; set; }

        private void Serve()
        {
            while (true)
            {
                HttpListenerContext context;
                try
                {
                    context = _listener.GetContext();
                }
                catch
                {
                    return;
                }

                var index = Interlocked.Increment(ref _requestCount) - 1;
                using (var reader = new StreamReader(context.Request.InputStream, Encoding.UTF8))
                {
                    _ = reader.ReadToEnd();
                }
                if (_hang)
                {
                    lock (_hungContexts)
                    {
                        _hungContexts.Add(context);
                    }
                    continue;
                }

                BeforeRespond?.Invoke(index);
                var (status, body) = _script[Math.Min(index, _script.Length - 1)];
                try
                {
                    var buffer = Encoding.UTF8.GetBytes(body);
                    context.Response.StatusCode = status;
                    context.Response.ContentType = "application/json";
                    context.Response.ContentLength64 = buffer.Length;
                    context.Response.OutputStream.Write(buffer, 0, buffer.Length);
                    context.Response.Close();
                }
                catch (HttpListenerException)
                {
                }
            }
        }

        public void Dispose()
        {
            lock (_hungContexts)
            {
                foreach (var context in _hungContexts)
                {
                    context.Response.Abort();
                }
            }
            _listener.Stop();
            _listener.Close();
            _thread.Join(TimeSpan.FromSeconds(2));
        }
    }
}

[CollectionDefinition(Name)]
public class TestNonceCollection
{
    public const string Name = "AuthForgeClient.TestNonceOverride";
}
