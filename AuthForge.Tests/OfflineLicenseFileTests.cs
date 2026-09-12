using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Net;
using System.Net.Sockets;
using System.Reflection;
using System.Text.Json;
using System.Threading;
using Xunit;

namespace AuthForge.Tests;

public class OfflineLicenseFileTests
{
    private sealed class OfflineVectors
    {
        public int Version { get; set; }
        public OfflineKeys Keys { get; set; } = new();
        public List<OfflineCase> Cases { get; set; } = new();
    }

    private sealed class OfflineKeys
    {
        public string SigningPublicKey { get; set; } = string.Empty;
        public string WrongPublicKey { get; set; } = string.Empty;
    }

    private sealed class OfflineCase
    {
        public string Name { get; set; } = string.Empty;
        public string AppId { get; set; } = string.Empty;
        public string PublicKey { get; set; } = string.Empty;
        public string Hwid { get; set; } = string.Empty;
        public string Now { get; set; } = string.Empty;
        public string File { get; set; } = string.Empty;
        public string Expect { get; set; } = string.Empty;
        public string? PayloadBase64 { get; set; }
        public string? SignatureBase64 { get; set; }
        public JsonElement? Payload { get; set; }
    }

    private static readonly JsonSerializerOptions Options = new() { PropertyNameCaseInsensitive = true };

    private static OfflineVectors LoadVectors()
    {
        var json = System.IO.File.ReadAllText("offline_license_vectors.json");
        var vectors = JsonSerializer.Deserialize<OfflineVectors>(json, Options)!;
        Assert.Equal(1, vectors.Version);
        Assert.True(vectors.Cases.Count >= 15);
        return vectors;
    }

    private static OfflineCase Case(OfflineVectors vectors, string name) =>
        vectors.Cases.Find(c => c.Name == name) ?? throw new InvalidOperationException($"case {name} missing");

    private static DateTimeOffset ParseNow(string value) =>
        DateTimeOffset.Parse(value, CultureInfo.InvariantCulture, DateTimeStyles.AssumeUniversal | DateTimeStyles.AdjustToUniversal);

    public static IEnumerable<object[]> VectorNames()
    {
        foreach (var c in LoadVectors().Cases)
        {
            yield return new object[] { c.Name };
        }
    }

    [Theory]
    [MemberData(nameof(VectorNames))]
    public void Every_Vector_Case_Matches_Expected(string name)
    {
        var vectors = LoadVectors();
        var c = Case(vectors, name);
        var result = AuthForgeClient.VerifyLicenseFile(c.File, c.AppId, new[] { c.PublicKey }, c.Hwid, ParseNow(c.Now));
        var got = result.Ok ? "ok" : result.Error;
        Assert.Equal(c.Expect, got);
        if (result.Ok && c.PayloadBase64 != null)
        {
            Assert.Equal(c.PayloadBase64, result.License!.PayloadBase64);
            Assert.Equal(c.SignatureBase64, result.License!.SignatureBase64);
        }
    }

    [Fact]
    public void Parse_Recovers_Canonical_Signed_String()
    {
        var vectors = LoadVectors();
        var good = Case(vectors, "good_bound");
        var parsed = AuthForgeClient.ParseLicenseFile(good.File);
        Assert.NotNull(parsed);
        Assert.Equal(good.PayloadBase64, parsed!.PayloadBase64);
        Assert.Equal(good.SignatureBase64, parsed.SignatureBase64);
        Assert.Equal("1", parsed.Headers["Version"]);
        Assert.Equal(good.AppId, parsed.Headers["App-Id"]);
        Assert.Null(AuthForgeClient.ParseLicenseFile("nope"));
    }

    [Fact]
    public void Good_File_Exposes_Entitlements()
    {
        var vectors = LoadVectors();
        var good = Case(vectors, "good_bound");
        var result = AuthForgeClient.VerifyLicenseFile(good.File, good.AppId, new[] { good.PublicKey }, good.Hwid, ParseNow(good.Now));
        Assert.True(result.Ok);
        var lic = result.License!;
        Assert.Equal("TEST-KEY0-0000-0000", lic.LicenseKey);
        Assert.Equal("kid-test-0001", lic.KeyId);
        Assert.Equal("bound", lic.HwidPolicy.Mode);
        Assert.Equal(new[] { "testhwid", "second-machine" }, lic.HwidPolicy.Hwids);
        Assert.Equal("Vector license", lic.Label);
        Assert.Equal("2027-01-01T00:00:00.000Z", lic.ExpiresAt);
        Assert.True(lic.LicenseExpirationPresent);
        Assert.Null(lic.LicenseExpiresAt);
        Assert.Equal("pro", lic.LicenseVariables!["tier"]!.ToString());
        Assert.Equal("dark", lic.AppVariables!["theme"]!.ToString());
    }

    private static (AuthForgeClient client, List<(string reason, string? code)> failures) MakeClient(
        OfflineCase good,
        string? appId = null,
        string? publicKey = null,
        string? hwid = null)
    {
        var failures = new List<(string, string?)>();
        var client = new AuthForgeClient(
            appId: appId ?? good.AppId,
            appSecret: string.Empty,
            publicKey: publicKey ?? good.PublicKey,
            apiBaseUrl: "http://127.0.0.1:9",
            onFailure: (reason, ex) => failures.Add((reason, ex?.Message)),
            hwidOverride: hwid ?? good.Hwid);
        return (client, failures);
    }

    [Fact]
    public void LoginFromFile_Is_Offline_And_Starts_No_Heartbeat()
    {
        var vectors = LoadVectors();
        var good = Case(vectors, "good_lifetime");
        var (client, failures) = MakeClient(good);

        Assert.Equal(good.Hwid, client.GetHwid());
        Assert.Null(client.GetSessionKind());
        Assert.True(client.LoginFromFile(good.File));
        Assert.True(client.IsAuthenticated());
        Assert.Equal(SessionKind.Offline, client.GetSessionKind());
        Assert.Equal("pro", client.GetLicenseVariables()!["tier"]!.ToString());
        Assert.Equal("dark", client.GetAppVariables()!["theme"]!.ToString());
        Assert.Equal("TEST-KEY0-0000-0000", client.GetSessionData()!["licenseKey"]!.ToString());
        var offline = client.GetOfflineLicense();
        Assert.NotNull(offline);
        Assert.Equal("00000000-0000-4000-8000-000000000003", offline!.Jti);
        Assert.Null(offline.ExpiresAt);
        Assert.Empty(failures);

        // No background thread was started.
        var threadField = typeof(AuthForgeClient).GetField("_heartbeatStarted", System.Reflection.BindingFlags.NonPublic | System.Reflection.BindingFlags.Instance)!;
        Assert.False((bool)threadField.GetValue(client)!);

        client.Logout();
        Assert.False(client.IsAuthenticated());
        Assert.Null(client.GetSessionKind());
        Assert.Null(client.GetOfflineLicense());
    }

    [Fact]
    public void Offline_SelfBan_Is_Local_Error_And_Never_Posts()
    {
        var vectors = LoadVectors();
        var good = Case(vectors, "good_lifetime");

        var port = GetFreeTcpPort();
        var prefix = $"http://127.0.0.1:{port}/";
        using var listener = new HttpListener();
        listener.Prefixes.Add(prefix);
        listener.Start();
        var requests = 0;
        listener.BeginGetContext(ar =>
        {
            try
            {
                var context = listener.EndGetContext(ar);
                Interlocked.Increment(ref requests);
                context.Response.StatusCode = 500;
                context.Response.Close();
            }
            catch (ObjectDisposedException)
            {
            }
            catch (HttpListenerException)
            {
            }
        }, null);

        try
        {
            var client = new AuthForgeClient(
                appId: good.AppId,
                appSecret: string.Empty,
                publicKey: good.PublicKey,
                apiBaseUrl: prefix.TrimEnd('/'),
                hwidOverride: good.Hwid);
            Assert.True(client.LoginFromFile(good.File));
            Assert.Equal(SessionKind.Offline, client.GetSessionKind());

            var ex = Assert.Throws<ArgumentException>(() => client.SelfBan());
            Assert.Equal("offline_session", ex.Message);

            // Still logged in offline; nothing was revoked or contacted.
            Assert.True(client.IsAuthenticated());
            Thread.Sleep(50);
            Assert.Equal(0, Volatile.Read(ref requests));
        }
        finally
        {
            listener.Stop();
            listener.Close();
        }
    }

    [Fact]
    public void Offline_Heartbeat_Entry_Point_Is_A_No_Op_Even_With_Online_Checkins()
    {
        var vectors = LoadVectors();
        var good = Case(vectors, "good_lifetime");
        var client = new AuthForgeClient(
            appId: good.AppId,
            appSecret: string.Empty,
            publicKey: good.PublicKey,
            onlineHeartbeat: true,
            heartbeatInterval: 10,
            apiBaseUrl: "http://127.0.0.1:9",
            hwidOverride: good.Hwid);

        Assert.True(client.LoginFromFile(good.File));

        // Drive the private start path the online login uses; offline sessions must ignore it.
        var start = typeof(AuthForgeClient).GetMethod("StartHeartbeatOnce", BindingFlags.NonPublic | BindingFlags.Instance)!;
        start.Invoke(client, null);

        var started = typeof(AuthForgeClient).GetField("_heartbeatStarted", BindingFlags.NonPublic | BindingFlags.Instance)!;
        var thread = typeof(AuthForgeClient).GetField("_heartbeatThread", BindingFlags.NonPublic | BindingFlags.Instance)!;
        Assert.False((bool)started.GetValue(client)!);
        Assert.Null(thread.GetValue(client));
        Assert.True(client.IsAuthenticated());
    }

    private static int GetFreeTcpPort()
    {
        var l = new TcpListener(IPAddress.Loopback, 0);
        l.Start();
        var port = ((IPEndPoint)l.LocalEndpoint).Port;
        l.Stop();
        return port;
    }

    [Fact]
    public void LoginFromFile_Rejects_Via_OnFailure()
    {
        var vectors = LoadVectors();
        var good = Case(vectors, "good_lifetime");

        var cases = new (Func<(AuthForgeClient, List<(string, string?)>)> make, string file, string expected)[]
        {
            (() => MakeClient(good), Case(vectors, "bad_signature_tampered_body").File, "bad_signature"),
            (() => MakeClient(good, publicKey: vectors.Keys.WrongPublicKey), good.File, "bad_signature"),
            (() => MakeClient(good), Case(vectors, "expired").File, "expired"),
            (() => MakeClient(good, hwid: "otherhwid"), good.File, "hwid_mismatch"),
            (() => MakeClient(good, appId: "other-app"), good.File, "wrong_app"),
            (() => MakeClient(good), Case(vectors, "unsupported_version").File, "unsupported_version"),
        };

        foreach (var (make, file, expected) in cases)
        {
            var (client, failures) = make();
            Assert.False(client.LoginFromFile(file));
            Assert.False(client.IsAuthenticated());
            Assert.Single(failures);
            Assert.Equal("offline_login_failed", failures[0].Item1);
            Assert.Equal(expected, failures[0].Item2);
        }
    }

    [Fact]
    public void LoginFromFile_Reads_From_Disk_And_Verify_Is_Side_Effect_Free()
    {
        var vectors = LoadVectors();
        var good = Case(vectors, "good_lifetime");
        var (client, failures) = MakeClient(good);

        var dir = Directory.CreateDirectory(Path.Combine(Path.GetTempPath(), "authforge-offline-" + Guid.NewGuid().ToString("N")));
        try
        {
            var path = Path.Combine(dir.FullName, "license.authforge");
            System.IO.File.WriteAllText(path, good.File);

            var checked_ = client.VerifyLicenseFile(path, ParseNow(good.Now));
            Assert.True(checked_.Ok);
            Assert.False(client.IsAuthenticated());

            Assert.True(client.LoginFromFile(path));
            Assert.True(client.IsAuthenticated());

            // Unreadable input never exits the process; it reports through OnFailure.
            Assert.False(client.LoginFromFile(Path.Combine(dir.FullName, "missing.authforge")));
            Assert.Single(failures);
            Assert.Equal("offline_login_failed", failures[0].reason);
        }
        finally
        {
            dir.Delete(recursive: true);
        }
    }

    private sealed class ActivationRequestVectors
    {
        public List<ActivationRequestCase> Cases { get; set; } = new();
    }

    private sealed class ActivationRequestCase
    {
        public string Name { get; set; } = string.Empty;
        public string File { get; set; } = string.Empty;
        public ActivationRequestInputs? Inputs { get; set; }
    }

    private sealed class ActivationRequestInputs
    {
        public string AppId { get; set; } = string.Empty;
        public string Hwid { get; set; } = string.Empty;
        public string CreatedAt { get; set; } = string.Empty;
        public string? MachineName { get; set; }
        public string? Os { get; set; }
        public string? Sdk { get; set; }
        public string? LicenseKey { get; set; }
    }

    [Fact]
    public void CreateActivationRequest_Matches_Vectors()
    {
        var json = File.ReadAllText("activation_request_vectors.json");
        var vectors = JsonSerializer.Deserialize<ActivationRequestVectors>(json, Options)!;
        const string dummyKey = "0wRcYWn44wk9tHOisXgso1wbtUqpFdy0IeMk4HXDiNc=";
        foreach (var c in vectors.Cases)
        {
            if (c.Inputs is null) continue;
            var client = new AuthForgeClient(
                appId: c.Inputs.AppId,
                appSecret: string.Empty,
                publicKey: dummyKey,
                hwidOverride: c.Inputs.Hwid);
            var got = client.CreateActivationRequest(new AuthForgeClient.ActivationRequestOptions
            {
                CreatedAt = c.Inputs.CreatedAt,
                OmitOs = string.IsNullOrEmpty(c.Inputs.Os),
                OmitSdk = string.IsNullOrEmpty(c.Inputs.Sdk),
                IncludeMachineName = !string.IsNullOrEmpty(c.Inputs.MachineName),
                MachineName = c.Inputs.MachineName,
                Os = c.Inputs.Os,
                Sdk = c.Inputs.Sdk,
                LicenseKey = c.Inputs.LicenseKey ?? ""
            });
            Assert.Equal(c.File, got);
            Assert.Equal(
                c.File,
                AuthForgeClient.FormatActivationRequest(
                    c.Inputs.AppId, c.Inputs.Hwid, c.Inputs.CreatedAt,
                    c.Inputs.MachineName, c.Inputs.Os, c.Inputs.Sdk, c.Inputs.LicenseKey));
        }
    }
}
