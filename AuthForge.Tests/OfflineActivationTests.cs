using System.IO;
using System.Net;
using System.Net.Sockets;
using System.Reflection;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;
using Xunit;

namespace AuthForge.Tests;

/// <summary>
/// Conformance tests for <see cref="AuthForgeClient.ActivateOffline"/> against
/// the shared <c>self_serve_activation_vectors.json</c>. In the nonce collection
/// because other tests set the static <c>TestNonceOverride</c>.
/// </summary>
[Collection(TestNonceCollection.Name)]
public class OfflineActivationTests
{
    private static readonly Regex NonceRegex = new("^[0-9a-f]{32}$");
    private static readonly string[] ExpectedBodyFields = { "appId", "appSecret", "licenseKey", "hwid", "nonce" };

    private static readonly Lazy<JsonDocument> VectorDocument = new(() =>
        JsonDocument.Parse(File.ReadAllText(Path.Combine(AppContext.BaseDirectory, "self_serve_activation_vectors.json"))));

    private static JsonElement Root => VectorDocument.Value.RootElement;
    private static JsonElement Config => Root.GetProperty("config");
    private static string Cfg(string name) => Config.GetProperty(name).GetString()!;

    private static JsonElement VectorCase(string name) =>
        Root.GetProperty("cases").EnumerateArray().First(c => c.GetProperty("name").GetString() == name);

    public static IEnumerable<object[]> CaseNames() =>
        Root.GetProperty("cases").EnumerateArray().Select(c => new object[] { c.GetProperty("name").GetString()! });

    [Fact]
    public void Vectors_Have_Expected_Shape()
    {
        Assert.Equal("authforge-self-serve-activation", Root.GetProperty("format").GetString());
        Assert.Equal(1, Root.GetProperty("version").GetInt32());
        var request = Root.GetProperty("request");
        Assert.Equal("POST", request.GetProperty("method").GetString());
        Assert.Equal("/auth/offline/activate", request.GetProperty("path").GetString());
        Assert.Equal(ExpectedBodyFields, request.GetProperty("bodyFields").EnumerateArray().Select(e => e.GetString()!));
        Assert.True(Root.GetProperty("cases").GetArrayLength() >= 17);
    }

    [Theory]
    [MemberData(nameof(CaseNames))]
    public void Vector_Case_Matches_Expected(string name)
    {
        var vector = VectorCase(name);
        var response = vector.GetProperty("response");
        var expect = vector.GetProperty("expect");
        var outcome = expect.GetProperty("outcome").GetString();

        using var server = ScriptedServer.Respond((response.GetProperty("status").GetInt32(), response.GetProperty("body").GetRawText()));
        using var temp = new TempDir();
        var harness = new Harness(server.BaseUrl);
        var client = harness.Client;
        var path = Path.Combine(temp.Path, "nested", "deeper", "license.authforge");
        const string original = "ORIGINAL CONTENT\r\nkeep me\n";

        if (outcome == "activated")
        {
            Assert.True(client.ActivateOffline(Cfg("licenseKey"), path));

            Assert.True(expect.GetProperty("writesFile").GetBoolean());
            var expectedBytes = new UTF8Encoding(false).GetBytes(expect.GetProperty("fileWritten").GetString()!);
            Assert.Equal(expectedBytes, File.ReadAllBytes(path));
            Assert.Equal(new[] { "license.authforge" }, Directory.GetFiles(Path.GetDirectoryName(path)!).Select(Path.GetFileName));

            Assert.True(client.IsAuthenticated());
            Assert.Equal(expect.GetProperty("sessionKind").GetString(), client.GetSessionKind()?.ToString().ToLowerInvariant());
            Assert.Equal(SessionKind.Offline, client.GetSessionKind());
            AssertVariables(expect.GetProperty("licenseVariables"), client.GetLicenseVariables());
            AssertVariables(expect.GetProperty("appVariables"), client.GetAppVariables());
            Assert.Equal(expect.GetProperty("replay").GetBoolean(), client.LastOfflineActivationReplay);

            var license = client.GetOfflineLicense();
            Assert.NotNull(license);
            Assert.Equal(response.GetProperty("body").GetProperty("jti").GetString(), license!.Jti);
            Assert.Equal(Cfg("licenseKey"), license.LicenseKey);
            Assert.Null(license.ExpiresAt);
            Assert.False(HeartbeatStarted(client));

            // Same state LoginFromFile would produce from the written file.
            var viaFile = new Harness(server.BaseUrl).Client;
            Assert.True(viaFile.LoginFromFile(path));
            Assert.Equal(viaFile.GetSessionData()!.Keys.OrderBy(k => k), client.GetSessionData()!.Keys.OrderBy(k => k));
        }
        else
        {
            Assert.Equal("error", outcome);
            Assert.False(expect.GetProperty("writesFile").GetBoolean());
            Directory.CreateDirectory(Path.GetDirectoryName(path)!);
            File.WriteAllText(path, original, new UTF8Encoding(false));

            var ex = Assert.Throws<AuthForgeException>(() => client.ActivateOffline(Cfg("licenseKey"), path));
            Assert.Equal(expect.GetProperty("errorCode").GetString(), ex.Code);
            var fatal = expect.GetProperty("fatal").GetBoolean();
            Assert.Equal(fatal, ex.IsFatal);
            Assert.Equal(!fatal, ex.IsTransient);
            Assert.Equal(!fatal, AuthForgeClient.IsTransientError(ex.Code));
            if (expect.TryGetProperty("detail", out var detail))
            {
                Assert.Contains(detail.GetString()!, ex.Message);
            }

            Assert.Equal(original, File.ReadAllText(path, Encoding.UTF8));
            Assert.Equal(new[] { "license.authforge" }, Directory.GetFiles(Path.GetDirectoryName(path)!).Select(Path.GetFileName));
            Assert.False(client.IsAuthenticated());
            Assert.Null(client.GetSessionKind());
            Assert.Null(client.GetOfflineLicense());
            Assert.Null(client.GetLicenseVariables());
            Assert.Null(client.LastOfflineActivationReplay);
            Assert.False(HeartbeatStarted(client));
        }

        // Never routed to onFailure / Environment.Exit.
        Assert.Empty(harness.Failures);
        Assert.Empty(harness.Exits);

        var requests = server.Requests;
        if (name == "error_rate_limited")
        {
            // Same retry policy as Login: 2s then 5s, fresh nonce each attempt.
            Assert.Equal(3, requests.Count);
            Assert.Equal(new[] { TimeSpan.FromSeconds(2), TimeSpan.FromSeconds(5) }, harness.Sleeps);
            Assert.Equal(3, requests.Select(r => r.Body["nonce"].GetString()).Distinct().Count());
        }
        else
        {
            Assert.Single(requests);
            Assert.Empty(harness.Sleeps);
        }
        foreach (var request in requests)
        {
            AssertActivationRequest(request, client);
        }
    }

    [Fact]
    public void Missing_App_Secret_Fails_Fast_Without_Request()
    {
        using var server = ScriptedServer.Respond((201, VectorCase("activated_new_machine").GetProperty("response").GetProperty("body").GetRawText()));
        using var temp = new TempDir();
        var path = Path.Combine(temp.Path, "license.authforge");
        foreach (var secret in new[] { "", null })
        {
            var harness = new Harness(server.BaseUrl, appSecret: secret);
            var ex = Assert.Throws<ArgumentException>(() => harness.Client.ActivateOffline(Cfg("licenseKey"), path));
            Assert.Contains("app_secret is required", ex.Message);
            Assert.False(harness.Client.IsAuthenticated());
            Assert.Empty(harness.Failures);
            Assert.Empty(harness.Exits);
        }
        Assert.Equal(0, server.RequestCount);
        Assert.False(File.Exists(path));
    }

    [Fact]
    public void Empty_License_Key_Is_Rejected_Without_Request()
    {
        using var server = ScriptedServer.Respond((500, "{}"));
        var harness = new Harness(server.BaseUrl);
        var ex = Assert.Throws<ArgumentException>(() => harness.Client.ActivateOffline("", null));
        Assert.Equal("licenseKey", ex.ParamName);

        // The license key is checked before the app secret.
        var noSecret = new Harness(server.BaseUrl, appSecret: "");
        ex = Assert.Throws<ArgumentException>(() => noSecret.Client.ActivateOffline("", null));
        Assert.Equal("licenseKey", ex.ParamName);
        Assert.Equal(0, server.RequestCount);
    }

    [Fact]
    public void Success_Without_Path_Writes_Nothing_And_Each_Call_Uses_A_Fresh_Nonce()
    {
        var body = VectorCase("activated_new_machine").GetProperty("response").GetProperty("body").GetRawText();
        using var server = ScriptedServer.Respond((201, body));
        var harness = new Harness(server.BaseUrl);

        Assert.True(harness.Client.ActivateOffline(Cfg("licenseKey")));
        Assert.True(harness.Client.ActivateOffline(Cfg("licenseKey"), null));

        Assert.Equal(SessionKind.Offline, harness.Client.GetSessionKind());
        Assert.True(harness.Client.IsAuthenticated());
        Assert.Equal(2, server.Requests.Count);
        Assert.NotEqual(server.Requests[0].Body["nonce"].GetString(), server.Requests[1].Body["nonce"].GetString());
    }

    [Fact]
    public void Success_Replaces_An_Existing_File_Byte_For_Byte()
    {
        var vector = VectorCase("activated_replay");
        using var server = ScriptedServer.Respond((200, vector.GetProperty("response").GetProperty("body").GetRawText()));
        using var temp = new TempDir();
        var path = Path.Combine(temp.Path, "license.authforge");
        // Pre-existing file with a BOM and CRLF: must be replaced exactly.
        File.WriteAllText(path, "old\r\nfile\r\n", new UTF8Encoding(true));

        var harness = new Harness(server.BaseUrl);
        Assert.True(harness.Client.ActivateOffline(Cfg("licenseKey"), path));

        var expected = Encoding.UTF8.GetBytes(vector.GetProperty("expect").GetProperty("fileWritten").GetString()!);
        Assert.Equal(expected, File.ReadAllBytes(path));
        Assert.Equal(new[] { "license.authforge" }, Directory.GetFiles(temp.Path).Select(Path.GetFileName));
        Assert.True(harness.Client.LastOfflineActivationReplay);
    }

    [Fact]
    public void Failure_Leaves_An_Existing_Session_Untouched()
    {
        var good = VectorCase("activated_new_machine").GetProperty("response").GetProperty("body").GetProperty("file").GetString()!;
        using var server = ScriptedServer.Respond((403, "{\"status\":\"failed\",\"error\":\"offline_activation_limit_reached\"}"));
        var harness = new Harness(server.BaseUrl);
        Assert.True(harness.Client.LoginFromFile(good));
        var licenseBefore = harness.Client.GetOfflineLicense();

        var ex = Assert.Throws<AuthForgeException>(() => harness.Client.ActivateOffline(Cfg("licenseKey")));
        Assert.Equal("offline_activation_limit_reached", ex.Code);
        Assert.True(harness.Client.IsAuthenticated());
        Assert.Equal(SessionKind.Offline, harness.Client.GetSessionKind());
        Assert.Same(licenseBefore, harness.Client.GetOfflineLicense());
        Assert.Empty(harness.Failures);
    }

    [Fact]
    public void Network_Failure_Without_OnFailure_Throws_And_Never_Exits()
    {
        var port = GetFreeTcpPort();
        var harness = new Harness($"http://127.0.0.1:{port}", withOnFailure: false, requestTimeout: 2);
        using var temp = new TempDir();
        var path = Path.Combine(temp.Path, "license.authforge");

        var ex = Assert.Throws<AuthForgeException>(() => harness.Client.ActivateOffline(Cfg("licenseKey"), path));
        Assert.True(ex.Code is "network_error" or "timeout", ex.Code);
        Assert.True(ex.IsTransient);
        Assert.Empty(harness.Exits);
        Assert.Empty(harness.Warnings);
        Assert.False(File.Exists(path));
        Assert.False(harness.Client.IsAuthenticated());
    }

    [Theory]
    [InlineData(200, "not json", "unexpected_response")]
    [InlineData(201, "{\"status\":\"success\",\"file\":42}", "unexpected_response")]
    [InlineData(201, "{\"status\":\"success\",\"file\":\"\"}", "unexpected_response")]
    [InlineData(200, "{\"status\":\"weird\"}", "unexpected_response")]
    [InlineData(502, "<html>bad gateway</html>", "http_error_502")]
    public void Malformed_Responses_Are_Transient_And_Write_Nothing(int status, string body, string code)
    {
        using var server = ScriptedServer.Respond((status, body));
        using var temp = new TempDir();
        var path = Path.Combine(temp.Path, "license.authforge");
        var harness = new Harness(server.BaseUrl, withOnFailure: false);

        var ex = Assert.Throws<AuthForgeException>(() => harness.Client.ActivateOffline(Cfg("licenseKey"), path));
        Assert.Equal(code, ex.Code);
        Assert.True(ex.IsTransient);
        Assert.False(File.Exists(path));
        Assert.Empty(Directory.GetFileSystemEntries(temp.Path));
        Assert.Empty(harness.Exits);
    }

    [Fact]
    public void Write_Failure_Throws_And_Leaves_Client_Unauthenticated()
    {
        using var server = ScriptedServer.Respond((201, VectorCase("activated_new_machine").GetProperty("response").GetProperty("body").GetRawText()));
        using var temp = new TempDir();
        // The target path is an existing directory, so the rename cannot succeed.
        var path = Path.Combine(temp.Path, "license.authforge");
        Directory.CreateDirectory(path);
        var harness = new Harness(server.BaseUrl);

        var ex = Assert.Throws<AuthForgeException>(() => harness.Client.ActivateOffline(Cfg("licenseKey"), path));
        Assert.Equal("file_write_failed", ex.Code);
        Assert.True(Directory.Exists(path));
        Assert.Equal(new[] { "license.authforge" }, Directory.GetFileSystemEntries(temp.Path).Select(Path.GetFileName));
        Assert.False(harness.Client.IsAuthenticated());
        Assert.Empty(harness.Exits);
    }

    [Fact]
    public void Sends_The_Same_Hwid_As_Login()
    {
        // No override: both requests must carry the derived HWID.
        using var server = ScriptedServer.Respond((401, "{\"status\":\"failed\",\"error\":\"invalid_key\"}"));
        var harness = new Harness(server.BaseUrl, hwidOverride: null);

        Assert.False(harness.Client.Login(Cfg("licenseKey")));
        Assert.Throws<AuthForgeException>(() => harness.Client.ActivateOffline(Cfg("licenseKey")));

        var requests = server.Requests;
        Assert.Equal(2, requests.Count);
        Assert.Equal("/auth/validate", requests[0].Path);
        Assert.Equal("/auth/offline/activate", requests[1].Path);
        var loginHwid = requests[0].Body["hwid"].GetString();
        Assert.False(string.IsNullOrEmpty(loginHwid));
        Assert.Equal(loginHwid, requests[1].Body["hwid"].GetString());
        Assert.Equal(harness.Client.GetHwid(), loginHwid);
    }

    private static void AssertActivationRequest(RecordedRequest request, AuthForgeClient client)
    {
        Assert.Equal("POST", request.Method);
        Assert.Equal("/auth/offline/activate", request.Path);
        Assert.Equal(ExpectedBodyFields.OrderBy(f => f, StringComparer.Ordinal), request.Body.Keys.OrderBy(k => k, StringComparer.Ordinal));
        Assert.Equal(Cfg("appId"), request.Body["appId"].GetString());
        Assert.Equal(Cfg("appSecret"), request.Body["appSecret"].GetString());
        Assert.Equal(Cfg("licenseKey"), request.Body["licenseKey"].GetString());
        Assert.Equal(Cfg("hwid"), request.Body["hwid"].GetString());
        Assert.Equal(client.GetHwid(), request.Body["hwid"].GetString());
        Assert.Matches(NonceRegex, request.Body["nonce"].GetString()!);
    }

    private static void AssertVariables(JsonElement expected, Dictionary<string, object?>? actual)
    {
        Assert.NotNull(actual);
        var expectedMap = expected.EnumerateObject().ToDictionary(p => p.Name, p => p.Value.GetRawText());
        var actualMap = actual!.ToDictionary(p => p.Key, p => JsonSerializer.Serialize(p.Value));
        Assert.Equal(expectedMap.OrderBy(p => p.Key), actualMap.OrderBy(p => p.Key));
    }

    private static bool HeartbeatStarted(AuthForgeClient client) =>
        (bool)typeof(AuthForgeClient).GetField("_heartbeatStarted", BindingFlags.NonPublic | BindingFlags.Instance)!.GetValue(client)!;

    private static int GetFreeTcpPort()
    {
        var l = new TcpListener(IPAddress.Loopback, 0);
        l.Start();
        var port = ((IPEndPoint)l.LocalEndpoint).Port;
        l.Stop();
        return port;
    }

    private sealed class Harness
    {
        private readonly object _gate = new();
        private readonly List<(string Reason, Exception? Error)> _failures = new();
        private readonly List<TimeSpan> _sleeps = new();
        private readonly List<int> _exits = new();
        private readonly List<string> _warnings = new();

        public Harness(
            string baseUrl,
            string? appSecret = "__config__",
            string? hwidOverride = "__config__",
            bool withOnFailure = true,
            int requestTimeout = 5)
        {
            Client = new AuthForgeClient(
                Cfg("appId"),
                appSecret == "__config__" ? Cfg("appSecret") : appSecret,
                Cfg("publicKey"),
                apiBaseUrl: baseUrl,
                onFailure: withOnFailure
                    ? (reason, ex) =>
                    {
                        lock (_gate)
                        {
                            _failures.Add((reason, ex));
                        }
                    }
                    : null,
                requestTimeout: requestTimeout,
                // Must never reach the activation body.
                ttlSeconds: 7200,
                hwidOverride: hwidOverride == "__config__" ? Cfg("hwid") : hwidOverride);
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

        public AuthForgeClient Client { get; }

        public IReadOnlyList<(string Reason, Exception? Error)> Failures
        {
            get { lock (_gate) { return _failures.ToList(); } }
        }

        public IReadOnlyList<TimeSpan> Sleeps
        {
            get { lock (_gate) { return _sleeps.ToList(); } }
        }

        public IReadOnlyList<int> Exits
        {
            get { lock (_gate) { return _exits.ToList(); } }
        }

        public IReadOnlyList<string> Warnings
        {
            get { lock (_gate) { return _warnings.ToList(); } }
        }
    }

    private sealed class TempDir : IDisposable
    {
        public TempDir()
        {
            Path = System.IO.Path.Combine(System.IO.Path.GetTempPath(), "authforge-activate-" + Guid.NewGuid().ToString("N"));
            Directory.CreateDirectory(Path);
        }

        public string Path { get; }

        public void Dispose()
        {
            try
            {
                Directory.Delete(Path, recursive: true);
            }
            catch
            {
                // Best effort.
            }
        }
    }

    private sealed record RecordedRequest(string Method, string Path, Dictionary<string, JsonElement> Body);

    private sealed class ScriptedServer : IDisposable
    {
        private readonly HttpListener _listener = new();
        private readonly (int Status, string Body)[] _script;
        private readonly List<RecordedRequest> _requests = new();
        private readonly Thread _thread;

        private ScriptedServer((int Status, string Body)[] script)
        {
            _script = script;
            BaseUrl = $"http://127.0.0.1:{GetFreeTcpPort()}";
            _listener.Prefixes.Add(BaseUrl + "/");
            _listener.Start();
            _thread = new Thread(Serve) { IsBackground = true };
            _thread.Start();
        }

        public static ScriptedServer Respond(params (int Status, string Body)[] script) => new(script);

        public string BaseUrl { get; }

        public IReadOnlyList<RecordedRequest> Requests
        {
            get { lock (_requests) { return _requests.ToList(); } }
        }

        public int RequestCount => Requests.Count;

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

                string raw;
                using (var reader = new StreamReader(context.Request.InputStream, Encoding.UTF8))
                {
                    raw = reader.ReadToEnd();
                }
                var body = new Dictionary<string, JsonElement>(StringComparer.Ordinal);
                try
                {
                    using var doc = JsonDocument.Parse(raw);
                    foreach (var property in doc.RootElement.EnumerateObject())
                    {
                        body[property.Name] = property.Value.Clone();
                    }
                }
                catch (JsonException)
                {
                }

                int index;
                lock (_requests)
                {
                    _requests.Add(new RecordedRequest(context.Request.HttpMethod, context.Request.Url!.AbsolutePath, body));
                    index = _requests.Count - 1;
                }

                var (status, responseBody) = _script[Math.Min(index, _script.Length - 1)];
                try
                {
                    var buffer = Encoding.UTF8.GetBytes(responseBody);
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
            _listener.Stop();
            _listener.Close();
            _thread.Join(TimeSpan.FromSeconds(2));
        }
    }
}
