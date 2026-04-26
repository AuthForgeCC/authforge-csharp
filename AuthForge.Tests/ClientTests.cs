using System.IO;
using System.Net;
using System.Net.Sockets;
using System.Reflection;
using System.Text;
using System.Text.Json;
using Xunit;

namespace AuthForge.Tests;

public class ClientTests
{
    private static readonly BindingFlags StaticNonPublic = BindingFlags.Static | BindingFlags.NonPublic;
    private const string TestPublicKey = "0wRcYWn44wk9tHOisXgso1wbtUqpFdy0IeMk4HXDiNc=";

    [Fact]
    public void IsAuthenticated_IsFalse_BeforeLogin()
    {
        var client = new AuthForgeClient(
            "test-app",
            "test-secret",
            TestPublicKey,
            "LOCAL",
            heartbeatInterval: 3600,
            apiBaseUrl: "http://127.0.0.1");

        Assert.False(client.IsAuthenticated());
    }

    [Theory]
    [InlineData("OFF")]
    [InlineData("")]
    [InlineData("CLIENT")]
    public void Constructor_RejectsInvalidHeartbeatMode(string mode)
    {
        var ex = Assert.Throws<ArgumentException>(() =>
            new AuthForgeClient("a", "b", TestPublicKey, mode, 900, apiBaseUrl: "http://127.0.0.1"));
        Assert.Equal("heartbeatMode", ex.ParamName);
    }

    [Fact]
    public void GenerateNonce_ProducesUniqueValues()
    {
        const int iterations = 64;
        var seen = new HashSet<string>(StringComparer.Ordinal);
        for (var i = 0; i < iterations; i++)
        {
            Assert.True(seen.Add(InvokeGenerateNonce()));
        }
    }

    private static string InvokeGenerateNonce()
    {
        var method = typeof(AuthForgeClient).GetMethod("GenerateNonce", StaticNonPublic);
        Assert.NotNull(method);
        return (string)method.Invoke(null, null)!;
    }

    [Fact]
    public void ValidateLicense_Success_DoesNotAuthenticate()
    {
        var vectorsPath = Path.Combine(AppContext.BaseDirectory, "test_vectors.json");
        using var vectorsDoc = JsonDocument.Parse(File.ReadAllText(vectorsPath));
        var successCase = vectorsDoc.RootElement.GetProperty("cases").EnumerateArray()
            .First(e => e.GetProperty("id").GetString() == "validate_success");
        var payload = successCase.GetProperty("payload").GetString()!;
        var signature = successCase.GetProperty("signature").GetString()!;
        var publicKey = vectorsDoc.RootElement.GetProperty("publicKey").GetString()!;

        var port = GetFreeTcpPort();
        var prefix = $"http://127.0.0.1:{port}/";
        using var listener = new HttpListener();
        listener.Prefixes.Add(prefix);
        listener.Start();

        var responseJson = JsonSerializer.Serialize(new Dictionary<string, object?>
        {
            ["status"] = "ok",
            ["payload"] = payload,
            ["signature"] = signature,
            ["keyId"] = "signing-key-1",
        });

        var serverThread = new Thread(() =>
        {
            var context = listener.GetContext();
            using var reader = new StreamReader(context.Request.InputStream, Encoding.UTF8);
            _ = reader.ReadToEnd();
            var buffer = Encoding.UTF8.GetBytes(responseJson);
            context.Response.StatusCode = 200;
            context.Response.ContentType = "application/json";
            context.Response.OutputStream.Write(buffer, 0, buffer.Length);
            context.Response.Close();
        })
        {
            IsBackground = true,
        };
        serverThread.Start();

        AuthForgeClient.TestNonceOverride = "nonce-validate-001";
        try
        {
            var client = new AuthForgeClient(
                "app-id",
                "app-secret",
                publicKey,
                "LOCAL",
                heartbeatInterval: 3600,
                apiBaseUrl: prefix.TrimEnd('/'));
            var result = client.ValidateLicense("license-key");
            Assert.True(result.Valid);
            Assert.False(client.IsAuthenticated());
        }
        finally
        {
            AuthForgeClient.TestNonceOverride = null;
            listener.Stop();
            listener.Close();
        }
    }

    [Fact]
    public void ValidateLicense_ServerError_IsNotValid()
    {
        var port = GetFreeTcpPort();
        var prefix = $"http://127.0.0.1:{port}/";
        using var listener = new HttpListener();
        listener.Prefixes.Add(prefix);
        listener.Start();

        var responseJson = "{\"status\":\"invalid_key\",\"error\":\"invalid_key\"}";

        var serverThread = new Thread(() =>
        {
            var context = listener.GetContext();
            using var reader = new StreamReader(context.Request.InputStream, Encoding.UTF8);
            _ = reader.ReadToEnd();
            var buffer = Encoding.UTF8.GetBytes(responseJson);
            context.Response.StatusCode = 200;
            context.Response.ContentType = "application/json";
            context.Response.OutputStream.Write(buffer, 0, buffer.Length);
            context.Response.Close();
        })
        {
            IsBackground = true,
        };
        serverThread.Start();

        try
        {
            var client = new AuthForgeClient(
                "app-id",
                "app-secret",
                TestPublicKey,
                "LOCAL",
                heartbeatInterval: 3600,
                apiBaseUrl: prefix.TrimEnd('/'));
            var result = client.ValidateLicense("bad");
            Assert.False(result.Valid);
            Assert.Equal("invalid_key", result.ErrorCode);
            Assert.False(client.IsAuthenticated());
        }
        finally
        {
            listener.Stop();
            listener.Close();
        }
    }

    // Valid Ed25519 public key (random) used purely as a "previous" entry in
    // the trust list, to exercise rotation handling without relying on the
    // wire-test signature.
    private const string DecoyPublicKey = "fKvaqROXtVWLV4h/AExsQetlJc811klm9ikLkt3fVbU=";

    [Fact]
    public void Constructor_AcceptsRotationSet_ViaIEnumerable()
    {
        var client = new AuthForgeClient(
            "app",
            "secret",
            new[] { DecoyPublicKey, TestPublicKey },
            "LOCAL",
            heartbeatInterval: 3600,
            apiBaseUrl: "http://127.0.0.1");
        Assert.Equal(2, client.PublicKeys.Count);
        Assert.Equal(DecoyPublicKey, client.PublicKey);
    }

    [Fact]
    public void Constructor_AcceptsRotationSet_ViaCommaSeparatedString()
    {
        var client = new AuthForgeClient(
            "app",
            "secret",
            DecoyPublicKey + "," + TestPublicKey,
            "LOCAL",
            heartbeatInterval: 3600,
            apiBaseUrl: "http://127.0.0.1");
        Assert.Equal(2, client.PublicKeys.Count);
    }

    private static int GetFreeTcpPort()
    {
        var l = new TcpListener(IPAddress.Loopback, 0);
        l.Start();
        var port = ((IPEndPoint)l.LocalEndpoint).Port;
        l.Stop();
        return port;
    }
}
