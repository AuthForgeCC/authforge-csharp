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
    public void Validate_DeriveKey_MatchesVectors()
    {
        var v = LoadValidateVectors();
        var client = CreateClient(v.AppSecret);

        var derived = InvokeDeriveValidateKey(client, v.Nonce);

        Assert.Equal(v.DerivedKeyHex, Convert.ToHexString(derived).ToLowerInvariant());
    }

    [Fact]
    public void Validate_SignPayload_VerifySignature_AcceptsExpectedHmac()
    {
        var v = LoadValidateVectors();
        var client = CreateClient(v.AppSecret);

        var derived = InvokeDeriveValidateKey(client, v.Nonce);

        var ex = Record.Exception(() => InvokeVerifySignature(v.Payload, derived, v.SignatureHex));
        Assert.Null(ex);
    }

    [Fact]
    public void Heartbeat_DeriveKey_MatchesVectors()
    {
        var h = LoadHeartbeatVectors();
        var client = CreateClient("unused-app-secret");
        SetPrivateField(client, "_sigKey", h.SigKey);

        var derived = InvokeDeriveHeartbeatKey(client, h.Nonce);

        Assert.Equal(h.DerivedKeyHex, Convert.ToHexString(derived).ToLowerInvariant());
    }

    [Fact]
    public void Heartbeat_SignPayload_VerifySignature_AcceptsExpectedHmac()
    {
        var h = LoadHeartbeatVectors();
        var client = CreateClient("unused-app-secret");
        SetPrivateField(client, "_sigKey", h.SigKey);

        var derived = InvokeDeriveHeartbeatKey(client, h.Nonce);

        var ex = Record.Exception(() => InvokeVerifySignature(h.Payload, derived, h.SignatureHex));
        Assert.Null(ex);
    }

    [Fact]
    public void Heartbeat_DeriveKey_Without_SigKey_Throws()
    {
        var client = CreateClient("app-secret");

        var invocation = Record.Exception(() => InvokeDeriveHeartbeatKey(client, "any-nonce"));
        Assert.NotNull(invocation);
        var inner = invocation is TargetInvocationException tie ? tie.InnerException : invocation;
        Assert.IsType<InvalidOperationException>(inner);
        Assert.Equal("missing_sig_key", inner!.Message);
    }

    [Fact]
    public void Validate_And_Heartbeat_Keys_Differ()
    {
        var v = LoadValidateVectors();
        var h = LoadHeartbeatVectors();
        Assert.NotEqual(v.DerivedKeyHex, h.DerivedKeyHex);
    }

    private static AuthForgeClient CreateClient(string appSecret) =>
        new(
            appId: "test-app-id",
            appSecret: appSecret,
            heartbeatMode: "LOCAL",
            heartbeatInterval: 900,
            apiBaseUrl: "http://127.0.0.1");

    private sealed record ValidateVectors(
        string AppSecret,
        string Nonce,
        string Payload,
        string DerivedKeyHex,
        string SignatureHex);

    private sealed record HeartbeatVectors(
        string SigKey,
        string Nonce,
        string Payload,
        string DerivedKeyHex,
        string SignatureHex);

    private static JsonDocument LoadVectorsDocument()
    {
        var path = Path.Combine(AppContext.BaseDirectory, "test_vectors.json");
        Assert.True(File.Exists(path), $"Missing {path}");
        return JsonDocument.Parse(File.ReadAllText(path));
    }

    private static ValidateVectors LoadValidateVectors()
    {
        using var doc = LoadVectorsDocument();
        var validate = doc.RootElement.GetProperty("validate");
        var inputs = validate.GetProperty("inputs");
        var outputs = validate.GetProperty("outputs");
        return new ValidateVectors(
            inputs.GetProperty("appSecret").GetString()!,
            inputs.GetProperty("nonce").GetString()!,
            inputs.GetProperty("payload").GetString()!,
            outputs.GetProperty("derivedKeyHex").GetString()!,
            outputs.GetProperty("signatureHex").GetString()!);
    }

    private static HeartbeatVectors LoadHeartbeatVectors()
    {
        using var doc = LoadVectorsDocument();
        var heartbeat = doc.RootElement.GetProperty("heartbeat");
        var inputs = heartbeat.GetProperty("inputs");
        var outputs = heartbeat.GetProperty("outputs");
        return new HeartbeatVectors(
            inputs.GetProperty("sigKey").GetString()!,
            inputs.GetProperty("nonce").GetString()!,
            inputs.GetProperty("payload").GetString()!,
            outputs.GetProperty("derivedKeyHex").GetString()!,
            outputs.GetProperty("signatureHex").GetString()!);
    }

    private static byte[] InvokeDeriveValidateKey(AuthForgeClient client, string nonce)
    {
        var method = typeof(AuthForgeClient).GetMethod("DeriveValidateKey", InstanceNonPublic);
        Assert.NotNull(method);
        return (byte[])method!.Invoke(client, new object[] { nonce })!;
    }

    private static byte[] InvokeDeriveHeartbeatKey(AuthForgeClient client, string nonce)
    {
        var method = typeof(AuthForgeClient).GetMethod("DeriveHeartbeatKey", InstanceNonPublic);
        Assert.NotNull(method);
        return (byte[])method!.Invoke(client, new object[] { nonce })!;
    }

    private static void InvokeVerifySignature(string rawPayloadB64, byte[] derivedKey, string signature)
    {
        var method = typeof(AuthForgeClient).GetMethod("VerifySignature", StaticNonPublic);
        Assert.NotNull(method);
        method!.Invoke(null, new object[] { rawPayloadB64, derivedKey, signature });
    }

    private static void SetPrivateField(AuthForgeClient client, string fieldName, object? value)
    {
        var field = typeof(AuthForgeClient).GetField(fieldName, InstanceNonPublic);
        Assert.NotNull(field);
        field!.SetValue(client, value);
    }
}
