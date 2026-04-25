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
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Signers;

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
        private readonly HashSet<string> _knownServerErrors = new HashSet<string>(StringComparer.Ordinal)
        {
            "invalid_app",
            "invalid_key",
            "expired",
            "revoked",
            "hwid_mismatch",
            "no_credits",
            "app_burn_cap_reached",
            "blocked",
            "rate_limited",
            "replay_detected",
            "app_disabled",
            "session_expired",
            "revoke_requires_session",
            "bad_request",
            "server_error",
            "system_error",
        };

        private Thread? _heartbeatThread;
        private bool _heartbeatStarted;
        private bool _heartbeatStop;

        private string? _licenseKey;
        private string? _sessionToken;
        private long? _sessionExpiresIn;
        private string? _lastNonce;
        private string? _rawPayloadB64;
        private string? _signature;
        private string? _keyId;
        private Dictionary<string, object?>? _sessionData;
        private Dictionary<string, object?>? _appVariables;
        private Dictionary<string, object?>? _licenseVariables;
        private bool _authenticated;
        private readonly string _hwid;

        public string AppId { get; }
        public string AppSecret { get; }
        public string PublicKey { get; }
        public string HeartbeatMode { get; }
        public int HeartbeatInterval { get; }
        public string ApiBaseUrl { get; }
        public Action<string, Exception?>? OnFailure { get; }
        public int RequestTimeout { get; }
        /// <summary>
        /// Requested session token lifetime (seconds) sent to /auth/validate.
        /// <c>null</c> (or &lt;= 0) means "let the server pick its default" (24h today).
        /// The server clamps to [3600, 604800]; out-of-range values are silently clamped.
        /// Heartbeats refresh the token while preserving the requested lifetime.
        /// </summary>
        public int? TtlSeconds { get; }

        private readonly Ed25519PublicKeyParameters _verifyPublicKey;

        public AuthForgeClient(
            string appId,
            string appSecret,
            string publicKey,
            string heartbeatMode,
            int heartbeatInterval = 900,
            string apiBaseUrl = DefaultApiBaseUrl,
            Action<string, Exception?>? onFailure = null,
            int requestTimeout = 15,
            int? ttlSeconds = null,
            string? hwidOverride = null)
        {
            if (string.IsNullOrEmpty(appId))
            {
                throw new ArgumentException("app_id must be a non-empty string", nameof(appId));
            }

            if (string.IsNullOrEmpty(appSecret))
            {
                throw new ArgumentException("app_secret must be a non-empty string", nameof(appSecret));
            }
            if (string.IsNullOrEmpty(publicKey))
            {
                throw new ArgumentException("public_key must be a non-empty string", nameof(publicKey));
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
            PublicKey = publicKey;
            HeartbeatMode = mode;
            HeartbeatInterval = heartbeatInterval;
            ApiBaseUrl = (apiBaseUrl ?? string.Empty).TrimEnd('/');
            OnFailure = onFailure;
            RequestTimeout = requestTimeout;
            TtlSeconds = ttlSeconds.HasValue && ttlSeconds.Value > 0 ? ttlSeconds : null;
            _httpClient = new HttpClient
            {
                Timeout = TimeSpan.FromSeconds(RequestTimeout),
            };
            byte[] publicKeyBytes;
            try
            {
                publicKeyBytes = Convert.FromBase64String(publicKey);
            }
            catch (FormatException ex)
            {
                throw new ArgumentException("public_key must be valid base64", nameof(publicKey), ex);
            }
            if (publicKeyBytes.Length != 32)
            {
                throw new ArgumentException("public_key must be 32 bytes (base64 Ed25519 raw key)", nameof(publicKey));
            }
            _verifyPublicKey = new Ed25519PublicKeyParameters(publicKeyBytes, 0);
            _hwid = ResolveHwid(hwidOverride);
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

        /// <summary>
        /// Performs the same <c>/auth/validate</c> request and Ed25519 verification as <see cref="Login"/>,
        /// without updating client session state or starting the heartbeat thread.
        /// </summary>
        public ValidateLicenseResult ValidateLicense(string licenseKey)
        {
            if (string.IsNullOrEmpty(licenseKey))
            {
                throw new ArgumentException("license_key must be a non-empty string", nameof(licenseKey));
            }

            try
            {
                var body = new Dictionary<string, object?>
                {
                    ["appId"] = AppId,
                    ["appSecret"] = AppSecret,
                    ["licenseKey"] = licenseKey,
                    ["hwid"] = _hwid,
                    ["nonce"] = GenerateNonce(),
                };
                if (TtlSeconds.HasValue)
                {
                    body["ttlSeconds"] = TtlSeconds.Value;
                }

                var responseObj = PostJson("/auth/validate", body, skipFailureOnNetwork: true);
                var expectedNonce = body.TryGetValue("nonce", out var usedNonce) ? (usedNonce?.ToString() ?? string.Empty) : string.Empty;
                var parsed = ParseSignedValidateResponse(responseObj, expectedNonce);
                var sessionData = ConvertToObjectMap(parsed.PayloadJson);
                var appVars = parsed.PayloadJson.TryGetValue("appVariables", out var appVarsElement)
                    ? ConvertJsonElementObject(appVarsElement)
                    : null;
                var licenseVars = parsed.PayloadJson.TryGetValue("licenseVariables", out var licenseVarsElement)
                    ? ConvertJsonElementObject(licenseVarsElement)
                    : null;
                return new ValidateLicenseResult
                {
                    Valid = true,
                    SessionToken = parsed.SessionToken,
                    ExpiresIn = parsed.ExpiresIn,
                    SessionData = new Dictionary<string, object?>(sessionData, StringComparer.Ordinal),
                    AppVariables = appVars is null ? null : new Dictionary<string, object?>(appVars, StringComparer.Ordinal),
                    LicenseVariables = licenseVars is null ? null : new Dictionary<string, object?>(licenseVars, StringComparer.Ordinal),
                    KeyId = parsed.KeyId,
                };
            }
            catch (Exception ex)
            {
                return new ValidateLicenseResult
                {
                    Valid = false,
                    ErrorCode = ex.Message,
                    Error = ex,
                };
            }
        }

        public Dictionary<string, object?> SelfBan(
            string? licenseKey = null,
            string? sessionToken = null,
            bool revokeLicense = true,
            bool blacklistHwid = true,
            bool blacklistIp = true)
        {
            string? currentSessionToken;
            string? currentLicenseKey;
            string hwid;
            lock (_lock)
            {
                currentSessionToken = _sessionToken;
                currentLicenseKey = _licenseKey;
                hwid = _hwid;
            }

            var resolvedSessionToken = string.IsNullOrWhiteSpace(sessionToken)
                ? currentSessionToken
                : sessionToken.Trim();
            if (!string.IsNullOrWhiteSpace(resolvedSessionToken))
            {
                var sessionBody = new Dictionary<string, object?>
                {
                    ["appId"] = AppId,
                    ["sessionToken"] = resolvedSessionToken,
                    ["hwid"] = hwid,
                    ["revokeLicense"] = revokeLicense,
                    ["blacklistHwid"] = blacklistHwid,
                    ["blacklistIp"] = blacklistIp,
                };
                var responseObj = PostJson("/auth/selfban", sessionBody);
                responseObj.TryGetValue("status", out var statusElement);
                if (!IsSuccessStatus(statusElement))
                {
                    throw new ArgumentException(ExtractServerError(responseObj));
                }
                return ConvertToObjectMap(responseObj);
            }

            var resolvedLicenseKey = string.IsNullOrWhiteSpace(licenseKey)
                ? currentLicenseKey
                : licenseKey.Trim();
            if (string.IsNullOrWhiteSpace(resolvedLicenseKey))
            {
                throw new ArgumentException("missing_license_key");
            }

            var preSessionBody = new Dictionary<string, object?>
            {
                ["appId"] = AppId,
                ["appSecret"] = AppSecret,
                ["licenseKey"] = resolvedLicenseKey,
                ["hwid"] = hwid,
                ["nonce"] = GenerateNonce(),
                // Pre-session self-ban cannot revoke licenses.
                ["revokeLicense"] = false,
                ["blacklistHwid"] = blacklistHwid,
                ["blacklistIp"] = blacklistIp,
            };
            var preSessionResponse = PostJson("/auth/selfban", preSessionBody);
            preSessionResponse.TryGetValue("status", out var preSessionStatus);
            if (!IsSuccessStatus(preSessionStatus))
            {
                throw new ArgumentException(ExtractServerError(preSessionResponse));
            }
            return ConvertToObjectMap(preSessionResponse);
        }

        private void StartHeartbeatOnce()
        {
            lock (_lock)
            {
                if (_heartbeatStarted)
                {
                    return;
                }

                _heartbeatStop = false;
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
                lock (_lock)
                {
                    if (_heartbeatStop)
                    {
                        break;
                    }
                }
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

            var body = new Dictionary<string, object?>
            {
                ["appId"] = AppId,
                ["sessionToken"] = sessionToken,
                ["nonce"] = GenerateNonce(),
                ["hwid"] = hwid,
            };
            var responseObj = PostJson("/auth/heartbeat", body);
            var expectedNonce = body.TryGetValue("nonce", out var usedNonce) ? (usedNonce?.ToString() ?? string.Empty) : string.Empty;
            ApplySignedResponse(responseObj, expectedNonce, null, "heartbeat");
        }

        private void LocalHeartbeat()
        {
            string? rawPayloadB64;
            string? signature;
            long? expiresIn;

            lock (_lock)
            {
                rawPayloadB64 = _rawPayloadB64;
                signature = _signature;
                expiresIn = _sessionExpiresIn;
            }

            if (string.IsNullOrEmpty(rawPayloadB64) || string.IsNullOrEmpty(signature))
            {
                throw new InvalidOperationException("missing_local_verification_state");
            }

            VerifySignature(rawPayloadB64, signature);

            if (expiresIn is null)
            {
                throw new InvalidOperationException("missing_session_expiry");
            }

            var now = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
            if (now < expiresIn.Value)
            {
                return;
            }
            throw new InvalidOperationException("session_expired");
        }

        private void ValidateAndStore(string licenseKey)
        {
            var body = new Dictionary<string, object?>
            {
                ["appId"] = AppId,
                ["appSecret"] = AppSecret,
                ["licenseKey"] = licenseKey,
                ["hwid"] = _hwid,
                ["nonce"] = GenerateNonce(),
            };
            if (TtlSeconds.HasValue)
            {
                body["ttlSeconds"] = TtlSeconds.Value;
            }
            var responseObj = PostJson("/auth/validate", body);
            var expectedNonce = body.TryGetValue("nonce", out var usedNonce) ? (usedNonce?.ToString() ?? string.Empty) : string.Empty;
            ApplySignedResponse(responseObj, expectedNonce, licenseKey, "validate");
        }

        private sealed class ParsedValidateSession
        {
            public string SessionToken { get; set; } = string.Empty;
            public long ExpiresIn { get; set; }
            public string RawPayloadB64 { get; set; } = string.Empty;
            public string Signature { get; set; } = string.Empty;
            public string? KeyId { get; set; }
            public Dictionary<string, JsonElement> PayloadJson { get; set; } = new(StringComparer.Ordinal);
        }

        private ParsedValidateSession ParseSignedValidateResponse(
            Dictionary<string, JsonElement> responseObj,
            string expectedNonce)
        {
            responseObj.TryGetValue("status", out var statusElement);
            if (!IsSuccessStatus(statusElement))
            {
                throw new ArgumentException(ExtractServerError(responseObj));
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

            VerifySignature(rawPayloadB64, signature);

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

            return new ParsedValidateSession
            {
                SessionToken = sessionToken,
                ExpiresIn = expiresIn.Value,
                RawPayloadB64 = rawPayloadB64,
                Signature = signature,
                KeyId = responseObj.TryGetValue("keyId", out var keyIdElement) ? keyIdElement.ToString() : null,
                PayloadJson = payloadJson,
            };
        }

        private void ApplySignedResponse(
            Dictionary<string, JsonElement> responseObj,
            string expectedNonce,
            string? licenseKey,
            string context)
        {
            var parsed = ParseSignedValidateResponse(responseObj, expectedNonce);
            _ = context;

            lock (_lock)
            {
                if (licenseKey is not null)
                {
                    _licenseKey = licenseKey;
                }

                _sessionToken = parsed.SessionToken;
                _sessionExpiresIn = parsed.ExpiresIn;
                _lastNonce = expectedNonce;
                _rawPayloadB64 = parsed.RawPayloadB64;
                _signature = parsed.Signature;
                _keyId = parsed.KeyId;
                _sessionData = ConvertToObjectMap(parsed.PayloadJson);
                _appVariables = parsed.PayloadJson.TryGetValue("appVariables", out var appVarsElement)
                    ? ConvertJsonElementObject(appVarsElement)
                    : null;
                _licenseVariables = parsed.PayloadJson.TryGetValue("licenseVariables", out var licenseVarsElement)
                    ? ConvertJsonElementObject(licenseVarsElement)
                    : null;
                _authenticated = true;
            }
        }

        private Dictionary<string, JsonElement> PostJson(string path, Dictionary<string, object?> data, bool skipFailureOnNetwork = false)
        {
            var url = $"{ApiBaseUrl}{path}";
            var body = new Dictionary<string, object?>(data, StringComparer.Ordinal);
            var rateRetryDelays = new[] { 2, 5 };
            var networkRetried = false;
            var rateAttempt = 0;

            while (true)
            {
                if (rateAttempt > 0 && body.ContainsKey("nonce"))
                {
                    body["nonce"] = GenerateNonce();
                    data["nonce"] = body["nonce"];
                }

                var payloadBytes = JsonSerializer.SerializeToUtf8Bytes(body, CompactJsonOptions);
                using var request = new HttpRequestMessage(HttpMethod.Post, url)
                {
                    Content = new ByteArrayContent(payloadBytes),
                };
                request.Content.Headers.ContentType = new System.Net.Http.Headers.MediaTypeHeaderValue("application/json");

                try
                {
                    using var response = _httpClient.SendAsync(request).GetAwaiter().GetResult();
                    var statusCode = (int)response.StatusCode;
                    var rawResponse = response.Content.ReadAsStringAsync().GetAwaiter().GetResult();
                    Dictionary<string, JsonElement> parsed;
                    try
                    {
                        parsed = ParseResponseObject(rawResponse);
                    }
                    catch
                    {
                        if (statusCode >= 400)
                        {
                            throw new InvalidOperationException($"http_error_{statusCode}");
                        }
                        throw;
                    }
                    var isRateLimited = statusCode == 429 || ExtractServerError(parsed) == "rate_limited";
                    if (isRateLimited && rateAttempt < rateRetryDelays.Length)
                    {
                        Thread.Sleep(TimeSpan.FromSeconds(rateRetryDelays[rateAttempt]));
                        rateAttempt++;
                        continue;
                    }
                    return parsed;
                }
                catch (HttpRequestException ex)
                {
                    if (!networkRetried)
                    {
                        networkRetried = true;
                        Thread.Sleep(TimeSpan.FromSeconds(2));
                        continue;
                    }
                    if (!skipFailureOnNetwork)
                    {
                        Fail("network_error", ex);
                    }
                    throw new InvalidOperationException($"url_error: {ex.Message}", ex);
                }
                catch (TaskCanceledException ex)
                {
                    if (!networkRetried)
                    {
                        networkRetried = true;
                        Thread.Sleep(TimeSpan.FromSeconds(2));
                        continue;
                    }
                    if (!skipFailureOnNetwork)
                    {
                        Fail("network_error", ex);
                    }
                    throw new InvalidOperationException($"url_error: {ex.Message}", ex);
                }
            }
        }

        private static Dictionary<string, JsonElement> ParseResponseObject(string rawResponse)
        {
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
            byte[] hash;
            using (var sha256 = SHA256.Create())
            {
                hash = sha256.ComputeHash(Encoding.UTF8.GetBytes(material));
            }
            return ToHexLower(hash);
        }

        private string ResolveHwid(string? hwidOverride)
        {
            var trimmed = (hwidOverride ?? string.Empty).Trim();
            return trimmed.Length > 0 ? trimmed : GetHwid();
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
                        return BitConverter.ToString(bytes).Replace("-", string.Empty).ToLowerInvariant();
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
                        process.Kill();
                    }
                    catch
                    {
                        // Ignore kill failures and return unavailable.
                    }

                    return "unavailable";
                }

                var output = process.StandardOutput.ReadToEnd();
                var cleaned = string.Join(" ", (output ?? string.Empty).Split((char[]?)null, StringSplitOptions.RemoveEmptyEntries));
                return string.IsNullOrEmpty(cleaned) ? "empty" : (cleaned.Length > 256 ? cleaned.Substring(0, 256) : cleaned);
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

        private static JsonDocument? TryDecodeSessionTokenBody(string sessionToken)
        {
            var parts = sessionToken.Split('.');
            if (parts.Length < 2)
            {
                return null;
            }

            var padded = AddBase64Padding(parts[0]);
            try
            {
                var normalized = padded.Replace('-', '+').Replace('_', '/');
                var decoded = Convert.FromBase64String(normalized);
                var doc = JsonDocument.Parse(decoded);
                if (doc.RootElement.ValueKind != JsonValueKind.Object)
                {
                    doc.Dispose();
                    return null;
                }
                return doc;
            }
            catch
            {
                return null;
            }
        }

        private static long? ExtractExpiresInFromSessionToken(string sessionToken)
        {
            using var doc = TryDecodeSessionTokenBody(sessionToken);
            if (doc is null)
            {
                return null;
            }

            if (!doc.RootElement.TryGetProperty("exp", out var expiresInElement))
            {
                return null;
            }

            try
            {
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

        private void VerifySignature(string rawPayloadB64, string signature)
        {
            byte[] signatureBytes;
            try
            {
                signatureBytes = Convert.FromBase64String(signature);
            }
            catch (FormatException ex)
            {
                throw new ArgumentException("invalid_signature", ex);
            }

            var verifier = new Ed25519Signer();
            verifier.Init(forSigning: false, _verifyPublicKey);
            var payloadBytes = Encoding.UTF8.GetBytes(rawPayloadB64);
            verifier.BlockUpdate(payloadBytes, 0, payloadBytes.Length);
            if (!verifier.VerifySignature(signatureBytes))
            {
                throw new ArgumentException("signature_mismatch");
            }
        }

        /// <summary>
        /// Integration test hook: when set, returned by <see cref="GenerateNonce"/> (same assembly only).
        /// </summary>
        internal static string? TestNonceOverride { get; set; }

        private static string GenerateNonce()
        {
            if (!string.IsNullOrEmpty(TestNonceOverride))
            {
                return TestNonceOverride!;
            }

            var bytes = new byte[16];
            using (var random = RandomNumberGenerator.Create())
            {
                random.GetBytes(bytes);
            }
            return ToHexStringCompat(bytes).ToLowerInvariant();
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

        private string ExtractServerError(Dictionary<string, JsonElement> responseObj)
        {
            if (responseObj.TryGetValue("error", out var errorElement))
            {
                var error = (errorElement.ToString() ?? string.Empty).Trim().ToLowerInvariant();
                if (_knownServerErrors.Contains(error))
                {
                    return error;
                }
            }

            if (responseObj.TryGetValue("status", out var statusElement))
            {
                var status = (statusElement.ToString() ?? string.Empty).Trim().ToLowerInvariant();
                if (_knownServerErrors.Contains(status))
                {
                    return status;
                }
            }

            return "unknown_error";
        }

        public void Logout()
        {
            lock (_lock)
            {
                _heartbeatStop = true;
                _heartbeatStarted = false;
                _heartbeatThread = null;
                _licenseKey = null;
                _sessionToken = null;
                _sessionExpiresIn = null;
                _lastNonce = null;
                _rawPayloadB64 = null;
                _signature = null;
                _keyId = null;
                _sessionData = null;
                _appVariables = null;
                _licenseVariables = null;
                _authenticated = false;
            }
        }

        public bool IsAuthenticated()
        {
            lock (_lock)
            {
                return _authenticated && !string.IsNullOrEmpty(_sessionToken);
            }
        }

        public Dictionary<string, object?>? GetSessionData()
        {
            lock (_lock)
            {
                return _sessionData is null ? null : new Dictionary<string, object?>(_sessionData, StringComparer.Ordinal);
            }
        }

        public Dictionary<string, object?>? GetAppVariables()
        {
            lock (_lock)
            {
                return _appVariables is null ? null : new Dictionary<string, object?>(_appVariables, StringComparer.Ordinal);
            }
        }

        public Dictionary<string, object?>? GetLicenseVariables()
        {
            lock (_lock)
            {
                return _licenseVariables is null ? null : new Dictionary<string, object?>(_licenseVariables, StringComparer.Ordinal);
            }
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
            return ToHexStringCompat(bytes).ToLowerInvariant();
        }

        private static string ToHexStringCompat(byte[] bytes)
        {
            return BitConverter.ToString(bytes).Replace("-", string.Empty);
        }

        private static Dictionary<string, object?>? ConvertJsonElementObject(JsonElement element)
        {
            if (element.ValueKind != JsonValueKind.Object)
            {
                return null;
            }

            return JsonSerializer.Deserialize<Dictionary<string, object?>>(element.GetRawText());
        }

        private static Dictionary<string, object?> ConvertToObjectMap(Dictionary<string, JsonElement> source)
        {
            var result = new Dictionary<string, object?>(StringComparer.Ordinal);
            foreach (var entry in source)
            {
                result[entry.Key] = JsonSerializer.Deserialize<object?>(entry.Value.GetRawText());
            }
            return result;
        }
    }

    public sealed class ValidateLicenseResult
    {
        public bool Valid { get; set; }
        public string? ErrorCode { get; set; }
        public Exception? Error { get; set; }
        public string? SessionToken { get; set; }
        public long? ExpiresIn { get; set; }
        public Dictionary<string, object?>? SessionData { get; set; }
        public Dictionary<string, object?>? AppVariables { get; set; }
        public Dictionary<string, object?>? LicenseVariables { get; set; }
        public string? KeyId { get; set; }
    }
}
