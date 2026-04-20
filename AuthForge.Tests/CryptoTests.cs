using System.Collections.Generic;
using System.Text.Json;
using Xunit;

namespace AuthForge.Tests;

public class CryptoTests
{
    [Fact]
    public void Vectors_Use_Ed25519_Algorithm()
    {
        var vectors = LoadVectors();
        Assert.Equal("ed25519", vectors.Algorithm);
    }

    [Fact]
    public void Constructor_Rejects_Invalid_PublicKey_Base64()
    {
        Assert.Throws<ArgumentException>(() => new AuthForgeClient(
            appId: "test-app-id",
            appSecret: "test-app-secret",
            publicKey: "not_base64",
            heartbeatMode: "LOCAL"));
    }

    [Theory]
    [MemberData(nameof(VectorCases))]
    public void VectorCase_Verification_MatchesExpected(string payload, string signature, bool shouldVerify)
    {
        var vectors = LoadVectors();
        var client = new AuthForgeClient(
            appId: "test-app-id",
            appSecret: "test-app-secret",
            publicKey: vectors.PublicKey,
            heartbeatMode: "LOCAL",
            apiBaseUrl: "http://127.0.0.1");

        var result = Record.Exception(() => InvokeVerifySignature(client, payload, signature));
        if (shouldVerify)
        {
            Assert.Null(result);
        }
        else
        {
            Assert.NotNull(result);
        }
    }

    public static IEnumerable<object[]> VectorCases()
    {
        var vectors = LoadVectors();
        foreach (var entry in vectors.Cases)
        {
            yield return new object[] { entry.Payload, entry.Signature, entry.ShouldVerify };
        }
    }

    private static void InvokeVerifySignature(AuthForgeClient client, string rawPayloadB64, string signature)
    {
        var method = typeof(AuthForgeClient).GetMethod("VerifySignature", System.Reflection.BindingFlags.Instance | System.Reflection.BindingFlags.NonPublic);
        Assert.NotNull(method);
        method!.Invoke(client, new object[] { rawPayloadB64, signature });
    }

    private static TestVectors LoadVectors()
    {
        var path = Path.Combine(AppContext.BaseDirectory, "test_vectors.json");
        var raw = File.ReadAllText(path);
        var vectors = JsonSerializer.Deserialize<TestVectors>(raw, new JsonSerializerOptions
        {
            PropertyNameCaseInsensitive = true,
        });
        Assert.NotNull(vectors);
        return vectors!;
    }

    private sealed record TestVectors(string Algorithm, string PublicKey, List<TestVectorCase> Cases);

    private sealed record TestVectorCase(string Id, string Payload, string Signature, bool ShouldVerify);
}
