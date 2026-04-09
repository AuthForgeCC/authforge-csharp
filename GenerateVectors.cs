using System;
using System.Collections.Generic;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using System.Text.Encodings.Web;
using System.Text.Json;

namespace AuthForge
{
    public static class GenerateVectors
    {
        private const string AppSecret = "af_test_secret_2026_reference";
        private const string Nonce = "0123456789abcdeffedcba9876543210";
        private const string SessionSigningSecret = "authforge-dev-session-signing-secret-rotate-before-production";
        private static readonly JsonSerializerOptions CompactJsonOptions = new JsonSerializerOptions
        {
            Encoder = JavaScriptEncoder.UnsafeRelaxedJsonEscaping,
        };

        private static string B64UrlNoPad(byte[] data)
        {
            return Convert.ToBase64String(data).TrimEnd('=').Replace('+', '-').Replace('/', '_');
        }

        private static string BuildRealisticSessionToken()
        {
            var body = new Dictionary<string, object?>
            {
                ["appId"] = "test-app",
                ["licenseKey"] = "test-key",
                ["hwid"] = "testhwid",
                ["appSecret"] = AppSecret,
                ["expiresIn"] = 1740433200,
            };

            var bodyJson = JsonSerializer.Serialize(body, CompactJsonOptions);
            var bodyB64 = B64UrlNoPad(Encoding.UTF8.GetBytes(bodyJson));

            byte[] digest;
            using (var hmac = new HMACSHA256(Encoding.UTF8.GetBytes(SessionSigningSecret)))
            {
                digest = hmac.ComputeHash(Encoding.UTF8.GetBytes(bodyB64));
            }

            var sigB64 = B64UrlNoPad(digest);
            return $"{bodyB64}.{sigB64}";
        }

        private static string BuildPayloadB64()
        {
            var payloadObj = new Dictionary<string, object?>
            {
                ["sessionToken"] = BuildRealisticSessionToken(),
                ["timestamp"] = 1740429600,
                ["expiresIn"] = 1740433200,
                ["nonce"] = Nonce,
            };

            var payloadJson = JsonSerializer.Serialize(payloadObj, CompactJsonOptions);
            return Convert.ToBase64String(Encoding.UTF8.GetBytes(payloadJson));
        }

        public static void Main()
        {
            var payload = BuildPayloadB64();

            var derivedKeyBytes = SHA256.HashData(Encoding.UTF8.GetBytes($"{AppSecret}{Nonce}"));

            string signatureHex;
            using (var hmac = new HMACSHA256(derivedKeyBytes))
            {
                var signatureBytes = hmac.ComputeHash(Encoding.UTF8.GetBytes(payload));
                signatureHex = Convert.ToHexString(signatureBytes).ToLowerInvariant();
            }

            var vectors = new Dictionary<string, object?>
            {
                ["algorithm"] = new Dictionary<string, object?>
                {
                    ["keyDerivation"] = "SHA256(appSecret + nonce)",
                    ["signature"] = "HMAC-SHA256(raw_base64_payload_string, derivedKey)",
                },
                ["inputs"] = new Dictionary<string, object?>
                {
                    ["appSecret"] = AppSecret,
                    ["nonce"] = Nonce,
                    ["payload"] = payload,
                },
                ["outputs"] = new Dictionary<string, object?>
                {
                    ["derivedKeyHex"] = Convert.ToHexString(derivedKeyBytes).ToLowerInvariant(),
                    ["signatureHex"] = signatureHex,
                },
            };

            var options = new JsonSerializerOptions
            {
                WriteIndented = true,
                Encoder = JavaScriptEncoder.UnsafeRelaxedJsonEscaping,
            };
            var json = JsonSerializer.Serialize(vectors, options);
            var outputPath = Path.Combine(Directory.GetCurrentDirectory(), "test_vectors.json");
            File.WriteAllText(outputPath, json, new UTF8Encoding(false));
            Console.WriteLine(outputPath);
        }
    }
}
