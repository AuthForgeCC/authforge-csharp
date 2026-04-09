using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Globalization;
using System.Linq;
using System.Net.Http;
using System.Net.NetworkInformation;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using System.Text.Encodings.Web;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;

namespace AuthForge
{
    public sealed class AuthForgeClient
    {
        private const string DefaultApiBaseUrl = "https://auth.authforge.cc";
        private static readonly JsonSerializerOptions CompactJsonOptions = new JsonSerializerOptions
        {
            Encoder = JavaScriptEncoder.UnsafeRelaxedJsonEscaping,
        };

        private readonly object _lock = new object();
        private readonly HttpClient _httpClient;

        private Thread? _heartbeatThread;
        private bool _heartbeatStarted;

        private string? _licenseKey;
        private string? _sessionToken;
        private long? _sessionExpiresIn;
        private string? _lastNonce;
        private string? _rawPayloadB64;
        private string? _signature;
        private byte[]? _derivedKey;
        private readonly string _hwid;

        public string AppId { get; }
        public string AppSecret { get; }
        public string HeartbeatMode { get; }
        public int HeartbeatInterval { get; }
        public string ApiBaseUrl { get; }
        public Action<string, Exception?>? OnFailure { get; }
        public int RequestTimeout { get; }

        public AuthForgeClient(
            string appId,
            string appSecret,
            string heartbeatMode,
            int heartbeatInterval = 900,
            string apiBaseUrl = DefaultApiBaseUrl,
            Action<string, Exception?>? onFailure = null,
            int requestTimeout = 15)
        {
            if (string.IsNullOrEmpty(appId))
            {
                throw new ArgumentException("app_id must be a non-empty string", nameof(appId));
            }

            if (string.IsNullOrEmpty(appSecret))
            {
                throw new ArgumentException("app_secret must be a non-empty string", nameof(appSecret));
            }

            var mode = (heartbeatMode ?? string.Empty).ToUpperInvariant();
            if (mode != "LOCAL" && mode != "SERVER")
            {
                throw new ArgumentException("heartbeat_mode must be LOCAL or SERVER", nameof(heartbeatMode));
            }

            if (heartbeatInterval <= 0)
            {
                throw new ArgumentException("heartbeat_interval must be > 0", nameof(heartbeatInterval));
            }

            AppId = appId;
            AppSecret = appSecret;
            HeartbeatMode = mode;
            HeartbeatInterval = heartbeatInterval;
            ApiBaseUrl = (apiBaseUrl ?? string.Empty).TrimEnd('/');
            OnFailure = onFailure;
            RequestTimeout = requestTimeout;
            _httpClient = new HttpClient
            {
                Timeout = TimeSpan.FromSeconds(RequestTimeout),
            };
            _hwid = GetHwid();
        }

        public bool Login(string licenseKey)
        {
            if (string.IsNullOrEmpty(licenseKey))
            {
                throw new ArgumentException("license_key must be a non-empty string", nameof(licenseKey));
            }

            try
            {
                ValidateAndStore(licenseKey);
                StartHeartbeatOnce();
                return true;
            }
            catch (Exception ex)
            {
                Fail("login_failed", ex);
                return false;
            }
        }

        private void StartHeartbeatOnce()
        {
            lock (_lock)
            {
                if (_heartbeatStarted)
                {
                    return;
                }

                _heartbeatStarted = true;
                _heartbeatThread = new Thread(HeartbeatLoop)
                {
                    Name = "AuthForgeHeartbeat",
                    IsBackground = true,
                };
                _heartbeatThread.Start();
            }
        }

        private void HeartbeatLoop()
        {
            while (true)
            {
                Thread.Sleep(TimeSpan.FromSeconds(HeartbeatInterval));
                try
                {
                    if (HeartbeatMode == "SERVER")
                    {
                        ServerHeartbeat();
                    }
                    else
                    {
                        LocalHeartbeat();
                    }
                }
                catch (Exception ex)
                {
                    Fail("heartbeat_failed", ex);
                    break;
                }
            }
        }

        private void ServerHeartbeat()
        {
            string? sessionToken;
            string hwid;
            lock (_lock)
            {
                sessionToken = _sessionToken;
                hwid = _hwid;
            }

            if (string.IsNullOrEmpty(sessionToken))
            {
                throw new InvalidOperationException("missing_session_token");
            }

            var nonce = GenerateNonce();
            var body = new Dictionary<string, object?>
            {
                ["appId"] = AppId,
                ["sessionToken"] = sessionToken,
                ["nonce"] = nonce,
                ["hwid"] = hwid,
            };
            var responseObj = PostJson("/auth/heartbeat", body);
            ApplySignedResponse(responseObj, nonce, null);
        }

        private void LocalHeartbeat()
        {
            string? rawPayloadB64;
            string? signature;
            byte[]? derivedKey;
            long? expiresIn;
            string? licenseKey;

            lock (_lock)
            {
                rawPayloadB64 = _rawPayloadB64;
                signature = _signature;
                derivedKey = _derivedKey;
                expiresIn = _sessionExpiresIn;
                licenseKey = _licenseKey;
            }

            if (string.IsNullOrEmpty(rawPayloadB64) || string.IsNullOrEmpty(signature) || derivedKey is null)
            {
                throw new InvalidOperationException("missing_local_verification_state");
            }

            VerifySignature(rawPayloadB64, derivedKey, signature);

            if (expiresIn is null)
            {
                throw new InvalidOperationException("missing_session_expiry");
            }

            var now = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
            if (now < expiresIn.Value)
            {
                return;
            }

            if (string.IsNullOrEmpty(licenseKey))
            {
                throw new InvalidOperationException("missing_license_key_for_refresh");
            }

            ValidateAndStore(licenseKey);
        }

        private void ValidateAndStore(string licenseKey)
        {
            var nonce = GenerateNonce();
            var body = new Dictionary<string, object?>
            {
                ["appId"] = AppId,
                ["appSecret"] = AppSecret,
                ["licenseKey"] = licenseKey,
                ["hwid"] = _hwid,
                ["nonce"] = nonce,
            };
            var responseObj = PostJson("/auth/validate", body);
            ApplySignedResponse(responseObj, nonce, licenseKey);
        }

        private void ApplySignedResponse(
            Dictionary<string, JsonElement> responseObj,
            string expectedNonce,
            string? licenseKey)
        {
            responseObj.TryGetValue("status", out var statusElement);
            if (!IsSuccessStatus(statusElement))
            {
                var statusText = statusElement.ValueKind == JsonValueKind.Undefined
                    ? "None"
                    : (statusElement.ToString() ?? string.Empty);
                if (statusElement.ValueKind == JsonValueKind.String)
                {
                    statusText = $"'{statusText}'";
                }

                throw new ArgumentException($"auth_status_not_success: {statusText}");
            }

            var rawPayloadB64 = RequireStr(responseObj, "payload");
            var signature = RequireStr(responseObj, "signature");
            var payloadJson = DecodePayloadJson(rawPayloadB64);

            var receivedNonce = payloadJson.TryGetValue("nonce", out var nonceElement)
                ? (nonceElement.ToString() ?? string.Empty).Trim()
                : string.Empty;
            if (!string.Equals(receivedNonce, expectedNonce, StringComparison.Ordinal))
            {
                throw new ArgumentException("nonce_mismatch");
            }

            var derivedKey = DeriveKey(expectedNonce);
            VerifySignature(rawPayloadB64, derivedKey, signature);

            var sessionToken = payloadJson.TryGetValue("sessionToken", out var sessionTokenElement)
                ? (sessionTokenElement.ToString() ?? string.Empty).Trim()
                : string.Empty;
            if (string.IsNullOrEmpty(sessionToken))
            {
                throw new ArgumentException("missing_sessionToken");
            }

            var expiresFromToken = ExtractExpiresInFromSessionToken(sessionToken);
            long? expiresFromPayload = null;
            if (payloadJson.TryGetValue("expiresIn", out var expiresElement) && expiresElement.ValueKind != JsonValueKind.Null)
            {
                expiresFromPayload = ConvertToInt64(expiresElement);
            }

            var expiresIn = expiresFromToken ?? expiresFromPayload;
            if (expiresIn is null)
            {
                throw new ArgumentException("missing_expiresIn");
            }

            lock (_lock)
            {
                if (licenseKey is not null)
                {
                    _licenseKey = licenseKey;
                }

                _sessionToken = sessionToken;
                _sessionExpiresIn = expiresIn.Value;
                _lastNonce = expectedNonce;
                _rawPayloadB64 = rawPayloadB64;
                _signature = signature;
                _derivedKey = derivedKey;
            }
        }

        private Dictionary<string, JsonElement> PostJson(string path, Dictionary<string, object?> data)
        {
            var url = $"{ApiBaseUrl}{path}";
            var payloadBytes = JsonSerializer.SerializeToUtf8Bytes(data, CompactJsonOptions);
            using var request = new HttpRequestMessage(HttpMethod.Post, url)
            {
                Content = new ByteArrayContent(payloadBytes),
            };
            request.Content.Headers.ContentType = new System.Net.Http.Headers.MediaTypeHeaderValue("application/json");

            HttpResponseMessage response;
            string rawResponse;
            try
            {
                response = _httpClient.Send(request);
                rawResponse = response.Content.ReadAsStringAsync().GetAwaiter().GetResult();
            }
            catch (HttpRequestException ex)
            {
                throw new InvalidOperationException($"url_error: {ex.Message}", ex);
            }
            catch (TaskCanceledException ex)
            {
                throw new InvalidOperationException($"url_error: {ex.Message}", ex);
            }

            if (!response.IsSuccessStatusCode)
            {
                var statusCode = (int)response.StatusCode;
                throw new InvalidOperationException($"http_error_{statusCode}: {rawResponse}");
            }

            JsonDocument document;
            try
            {
                document = JsonDocument.Parse(rawResponse);
            }
            catch (JsonException ex)
            {
                throw new ArgumentException("invalid_json_response", ex);
            }

            using (document)
            {
                if (document.RootElement.ValueKind != JsonValueKind.Object)
                {
                    throw new ArgumentException("response_not_json_object");
                }

                var result = new Dictionary<string, JsonElement>(StringComparer.Ordinal);
                foreach (var property in document.RootElement.EnumerateObject())
                {
                    result[property.Name] = property.Value.Clone();
                }

                return result;
            }
        }

        private string GetHwid()
        {
            var mac = SafeMacAddress();
            var cpu = SafeCpuInfo();
            var disk = SafeDiskSerial();
            var material = $"mac:{mac}|cpu:{cpu}|disk:{disk}";
            var hash = SHA256.HashData(Encoding.UTF8.GetBytes(material));
            return ToHexLower(hash);
        }

        private string SafeMacAddress()
        {
            try
            {
                foreach (var networkInterface in NetworkInterface.GetAllNetworkInterfaces())
                {
                    var bytes = networkInterface.GetPhysicalAddress().GetAddressBytes();
                    if (bytes.Length > 0)
                    {
                        return BitConverter.ToString(bytes).Replace("-", string.Empty, StringComparison.Ordinal).ToLowerInvariant();
                    }
                }

                return "mac-unavailable";
            }
            catch
            {
                return "mac-unavailable";
            }
        }

        private string SafeCpuInfo()
        {
            try
            {
                var value = $"{Environment.ProcessorCount}-{RuntimeInformation.ProcessArchitecture}";
                return string.IsNullOrWhiteSpace(value) ? "cpu-unavailable" : value;
            }
            catch
            {
                return "cpu-unavailable";
            }
        }

        private string SafeDiskSerial()
        {
            var system = RuntimeInformation.OSDescription.ToLowerInvariant();
            try
            {
                if (system.Contains("windows", StringComparison.Ordinal))
                {
                    return RunCommand("wmic", "diskdrive get serialnumber");
                }

                if (system.Contains("linux", StringComparison.Ordinal))
                {
                    var outText = RunCommand("lsblk", "-ndo SERIAL");
                    if (!string.IsNullOrWhiteSpace(outText))
                    {
                        return outText;
                    }

                    return RunCommand("udevadm", "info --query=property --name=sda");
                }

                if (system.Contains("darwin", StringComparison.Ordinal) || RuntimeInformation.IsOSPlatform(OSPlatform.OSX))
                {
                    return RunCommand("system_profiler", "SPStorageDataType");
                }
            }
            catch
            {
                return "disk-unavailable";
            }

            return "disk-unavailable";
        }

        private static string RunCommand(string fileName, string arguments)
        {
            try
            {
                var startInfo = new ProcessStartInfo
                {
                    FileName = fileName,
                    Arguments = arguments,
                    RedirectStandardOutput = true,
                    RedirectStandardError = true,
                    UseShellExecute = false,
                    CreateNoWindow = true,
                };

                using var process = Process.Start(startInfo);
                if (process is null)
                {
                    return "unavailable";
                }

                if (!process.WaitForExit(2000))
                {
                    try
                    {
                        process.Kill(entireProcessTree: true);
                    }
                    catch
                    {
                        // Ignore kill failures and return unavailable.
                    }

                    return "unavailable";
                }

                var output = process.StandardOutput.ReadToEnd();
                var cleaned = string.Join(" ", (output ?? string.Empty).Split((char[]?)null, StringSplitOptions.RemoveEmptyEntries));
                return string.IsNullOrEmpty(cleaned) ? "empty" : (cleaned.Length > 256 ? cleaned[..256] : cleaned);
            }
            catch
            {
                return "unavailable";
            }
        }

        private static Dictionary<string, JsonElement> DecodePayloadJson(string payloadB64)
        {
            var payloadBytes = DecodeBase64Any(payloadB64);
            JsonDocument doc;
            try
            {
                doc = JsonDocument.Parse(payloadBytes);
            }
            catch (Exception ex)
            {
                throw new ArgumentException("invalid_payload_json", ex);
            }

            using (doc)
            {
                if (doc.RootElement.ValueKind != JsonValueKind.Object)
                {
                    throw new ArgumentException("payload_not_json_object");
                }

                var result = new Dictionary<string, JsonElement>(StringComparer.Ordinal);
                foreach (var property in doc.RootElement.EnumerateObject())
                {
                    result[property.Name] = property.Value.Clone();
                }

                return result;
            }
        }

        private static byte[] DecodeBase64Any(string value)
        {
            var padded = AddBase64Padding(value);
            try
            {
                return Convert.FromBase64String(padded);
            }
            catch
            {
                var normalized = padded.Replace('-', '+').Replace('_', '/');
                return Convert.FromBase64String(normalized);
            }
        }

        private static long? ExtractExpiresInFromSessionToken(string sessionToken)
        {
            var parts = sessionToken.Split('.');
            if (parts.Length < 2)
            {
                return null;
            }

            var payloadPart = parts[0];
            var padded = AddBase64Padding(payloadPart);
            try
            {
                var normalized = padded.Replace('-', '+').Replace('_', '/');
                var decoded = Convert.FromBase64String(normalized);
                using var payloadDoc = JsonDocument.Parse(decoded);
                if (payloadDoc.RootElement.ValueKind != JsonValueKind.Object)
                {
                    return null;
                }

                if (!payloadDoc.RootElement.TryGetProperty("expiresIn", out var expiresInElement))
                {
                    return null;
                }

                return ConvertToInt64(expiresInElement);
            }
            catch
            {
                return null;
            }
        }

        private static string AddBase64Padding(string text)
        {
            var remainder = text.Length % 4;
            if (remainder == 0)
            {
                return text;
            }

            return text + new string('=', 4 - remainder);
        }

        private byte[] DeriveKey(string nonce)
        {
            var seed = Encoding.UTF8.GetBytes($"{AppSecret}{nonce}");
            return SHA256.HashData(seed);
        }

        private static void VerifySignature(string rawPayloadB64, byte[] derivedKey, string signature)
        {
            using var hmac = new HMACSHA256(derivedKey);
            var expectedBytes = hmac.ComputeHash(Encoding.UTF8.GetBytes(rawPayloadB64));
            var expected = ToHexLower(expectedBytes);
            var received = (signature ?? string.Empty).Trim().ToLowerInvariant();
            if (!CryptographicOperations.FixedTimeEquals(
                    Encoding.ASCII.GetBytes(expected),
                    Encoding.ASCII.GetBytes(received)))
            {
                throw new ArgumentException("signature_mismatch");
            }
        }

        private static string GenerateNonce()
        {
            var bytes = new byte[16];
            RandomNumberGenerator.Fill(bytes);
            return Convert.ToHexString(bytes).ToLowerInvariant();
        }

        private static bool IsSuccessStatus(JsonElement status)
        {
            if (status.ValueKind == JsonValueKind.True)
            {
                return true;
            }

            if (status.ValueKind == JsonValueKind.False || status.ValueKind == JsonValueKind.Null || status.ValueKind == JsonValueKind.Undefined)
            {
                return false;
            }

            var value = (status.ToString() ?? string.Empty).Trim().ToLowerInvariant();
            return value == "ok" || value == "success" || value == "valid" || value == "true" || value == "1";
        }

        private static string RequireStr(Dictionary<string, JsonElement> obj, string key)
        {
            if (!obj.TryGetValue(key, out var value) || value.ValueKind == JsonValueKind.Null || value.ValueKind == JsonValueKind.Undefined)
            {
                throw new ArgumentException($"missing_{key}");
            }

            var text = value.ToString() ?? string.Empty;
            if (text.Length == 0)
            {
                throw new ArgumentException($"empty_{key}");
            }

            return text;
        }

        private void Fail(string reason, Exception? ex = null)
        {
            if (OnFailure is not null)
            {
                try
                {
                    OnFailure(reason, ex);
                    return;
                }
                catch
                {
                    // Match Python behavior: callback failure falls through to exit.
                }
            }

            Environment.Exit(1);
        }

        private static long ConvertToInt64(JsonElement element)
        {
            if (element.ValueKind == JsonValueKind.Number && element.TryGetInt64(out var int64Value))
            {
                return int64Value;
            }

            var text = element.ToString();
            if (text is null)
            {
                throw new ArgumentException("invalid_integer_value");
            }

            return long.Parse(text, NumberStyles.Integer, CultureInfo.InvariantCulture);
        }

        private static string ToHexLower(byte[] bytes)
        {
            return Convert.ToHexString(bytes).ToLowerInvariant();
        }
    }
}
