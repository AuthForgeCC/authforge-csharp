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
        private const string SigKey = "af_test_sig_key_2026_reference_0123456789abcdef";
        private const string Nonce = "0123456789abcdeffedcba9876543210";
        private const string SessionSigningSecret = "authforge-dev-session-signing-secret-rotate-before-production";
        private const long ExpiresIn = 1740433200L;
        private const long Timestamp = 1740429600L;
        private static readonly JsonSerializerOptions CompactJsonOptions = new JsonSerializerOptions
        {
            Encoder = JavaScriptEncoder.UnsafeRelaxedJsonEscaping,
        };

        private static string B64UrlNoPad(byte[] data)
        {
            return Convert.ToBase64String(data).TrimEnd('=').Replace('+', '-').Replace('/', '_');
        }

        private static string BuildSessionToken()
        {
            var body = new Dictionary<string, object?>
            {
                ["appId"] = "test-app",
                ["licenseKey"] = "test-key",
                ["hwid"] = "testhwid",
                ["sigKey"] = SigKey,
                ["expiresIn"] = ExpiresIn,
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
                ["sessionToken"] = BuildSessionToken(),
                ["timestamp"] = Timestamp,
                ["expiresIn"] = ExpiresIn,
                ["nonce"] = Nonce,
            };

            var payloadJson = JsonSerializer.Serialize(payloadObj, CompactJsonOptions);
            return Convert.ToBase64String(Encoding.UTF8.GetBytes(payloadJson));
        }

        private static string SignHex(byte[] key, string message)
        {
            using var hmac = new HMACSHA256(key);
            var bytes = hmac.ComputeHash(Encoding.UTF8.GetBytes(message));
            return Convert.ToHexString(bytes).ToLowerInvariant();
        }

        public static void Main()
        {
            var payload = BuildPayloadB64();

            var validateKey = SHA256.HashData(Encoding.UTF8.GetBytes($"{AppSecret}{Nonce}"));
            var validateSig = SignHex(validateKey, payload);

            var heartbeatKey = SHA256.HashData(Encoding.UTF8.GetBytes($"{SigKey}{Nonce}"));
            var heartbeatSig = SignHex(heartbeatKey, payload);

            var vectors = new Dictionary<string, object?>
            {
                ["validate"] = new Dictionary<string, object?>
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
                        ["derivedKeyHex"] = Convert.ToHexString(validateKey).ToLowerInvariant(),
                        ["signatureHex"] = validateSig,
                    },
                },
                ["heartbeat"] = new Dictionary<string, object?>
                {
                    ["algorithm"] = new Dictionary<string, object?>
                    {
                        ["keyDerivation"] = "SHA256(sigKey + nonce)",
                        ["signature"] = "HMAC-SHA256(raw_base64_payload_string, derivedKey)",
                    },
                    ["inputs"] = new Dictionary<string, object?>
                    {
                        ["sigKey"] = SigKey,
                        ["nonce"] = Nonce,
                        ["payload"] = payload,
                    },
                    ["outputs"] = new Dictionary<string, object?>
                    {
                        ["derivedKeyHex"] = Convert.ToHexString(heartbeatKey).ToLowerInvariant(),
                        ["signatureHex"] = heartbeatSig,
                    },
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
