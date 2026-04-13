using System.Reflection;
using System.Text.Json;
using Xunit;

namespace AuthForge.Tests;

/// <summary>
/// Cross-SDK compatibility checks against shared <c>test_vectors.json</c>.
/// Uses reflection to exercise <see cref="AuthForgeClient"/>'s private key derivation and signature verification.
/// </summary>
public class CryptoTests
{
    private static readonly BindingFlags InstanceNonPublic = BindingFlags.Instance | BindingFlags.NonPublic;
    private static readonly BindingFlags StaticNonPublic = BindingFlags.Static | BindingFlags.NonPublic;

    [Fact]
    public void TestVectors_DeriveSigningKey_MatchesExpected()
    {
        var v = LoadVectors();
        var client = CreateClient(v.AppSecret);

        var derived = InvokeDeriveKey(client, v.Nonce);

        Assert.Equal(v.DerivedKeyHex, Convert.ToHexString(derived).ToLowerInvariant());
    }

    [Fact]
    public void TestVectors_SignPayload_VerifySignature_AcceptsExpectedHmac()
    {
        var v = LoadVectors();
        var client = CreateClient(v.AppSecret);

        var derived = InvokeDeriveKey(client, v.Nonce);

        var ex = Record.Exception(() => InvokeVerifySignature(v.Payload, derived, v.SignatureHex));
        Assert.Null(ex);
    }

    private static AuthForgeClient CreateClient(string appSecret) =>
        new(
            appId: "test-app-id",
            appSecret: appSecret,
            heartbeatMode: "LOCAL",
            heartbeatInterval: 900,
            apiBaseUrl: "http://127.0.0.1");

    private sealed record TestVectors(
        string AppSecret,
        string Nonce,
        string Payload,
        string DerivedKeyHex,
        string SignatureHex);

    private static TestVectors LoadVectors()
    {
        var path = Path.Combine(AppContext.BaseDirectory, "test_vectors.json");
        Assert.True(File.Exists(path), $"Missing {path}");

        using var doc = JsonDocument.Parse(File.ReadAllText(path));
        var inputs = doc.RootElement.GetProperty("inputs");
        var outputs = doc.RootElement.GetProperty("outputs");
        return new TestVectors(
            inputs.GetProperty("appSecret").GetString()!,
            inputs.GetProperty("nonce").GetString()!,
            inputs.GetProperty("payload").GetString()!,
            outputs.GetProperty("derivedKeyHex").GetString()!,
            outputs.GetProperty("signatureHex").GetString()!);
    }

    private static byte[] InvokeDeriveKey(AuthForgeClient client, string nonce)
    {
        var method = typeof(AuthForgeClient).GetMethod("DeriveKey", InstanceNonPublic);
        Assert.NotNull(method);
        return (byte[])method.Invoke(client, new object[] { nonce })!;
    }

    private static void InvokeVerifySignature(string rawPayloadB64, byte[] derivedKey, string signature)
    {
        var method = typeof(AuthForgeClient).GetMethod("VerifySignature", StaticNonPublic);
        Assert.NotNull(method);
        method.Invoke(null, new object[] { rawPayloadB64, derivedKey, signature });
    }
}
