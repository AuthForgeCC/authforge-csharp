using System.Reflection;
using Xunit;

namespace AuthForge.Tests;

public class ClientTests
{
    private static readonly BindingFlags StaticNonPublic = BindingFlags.Static | BindingFlags.NonPublic;

    [Fact]
    public void IsAuthenticated_IsFalse_BeforeLogin()
    {
        var client = new AuthForgeClient(
            "test-app",
            "test-secret",
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
            new AuthForgeClient("a", "b", mode, 900, apiBaseUrl: "http://127.0.0.1"));
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
}
