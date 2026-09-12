using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Signers;

namespace AuthForge
{
    /// <summary>
    /// Offline license files (<c>.authforge</c>).
    ///
    /// A cloud-minted, Ed25519-signed document for machines that never phone
    /// home. This is a <b>separate</b> mode from the grace period: the grace
    /// period continues a signed session after one online activation, while
    /// an offline file is verified locally with only the app public key and
    /// the machine HWID. Nothing in this file performs network I/O or starts
    /// online check-ins.
    ///
    /// Format (version 1): PEM-style armor with informational headers, a
    /// base64 JSON payload wrapped at 64 columns, and a detached Ed25519
    /// signature over the UTF-8 bytes of the base64 payload string (body
    /// lines joined, whitespace removed) - the same contract as
    /// <c>/auth/validate</c>.
    /// </summary>
    public sealed partial class AuthForgeClient
    {
        /// <summary>The only <c>.authforge</c> format version this SDK accepts.</summary>
        public const int OfflineLicenseFileVersion = 1;

        private const string OfflineBeginLicense = "-----BEGIN AUTHFORGE LICENSE-----";
        private const string OfflineEndLicense = "-----END AUTHFORGE LICENSE-----";
        private const string OfflineBeginSignature = "-----BEGIN AUTHFORGE SIGNATURE-----";
        private const string OfflineEndSignature = "-----END AUTHFORGE SIGNATURE-----";
        private static readonly Regex OfflineBase64Regex = new Regex("^[A-Za-z0-9+/]+={0,2}$", RegexOptions.Compiled);
        private static readonly Regex WhitespaceRegex = new Regex(@"\s+", RegexOptions.Compiled);

        /// <summary>
        /// The HWID this client sends to AuthForge (or <c>hwidOverride</c>).
        /// Customers on air-gapped machines report this value to the operator so
        /// an offline <c>.authforge</c> file can be bound to it.
        /// </summary>
        public string GetHwid() => _hwid;

        /// <summary>
        /// Optional fields for <see cref="CreateActivationRequest"/>.
        /// <c>MachineName</c> is omitted unless <see cref="ActivationRequestOptions.IncludeMachineName"/> is true.
        /// </summary>
        public sealed class ActivationRequestOptions
        {
            public bool IncludeMachineName { get; set; }
            public string? MachineName { get; set; }
            public string? Os { get; set; }
            public bool OmitOs { get; set; }
            public string? Sdk { get; set; }
            public bool OmitSdk { get; set; }
            public string? LicenseKey { get; set; }
            public string? CreatedAt { get; set; }
        }

        private const int ActivationRequestVersion = 1;
        private const string ActivationRequestTyp = "authforge-activation-request";
        private const string BeginActivationRequest = "-----BEGIN AUTHFORGE ACTIVATION REQUEST-----";
        private const string EndActivationRequest = "-----END AUTHFORGE ACTIVATION REQUEST-----";
        private const string ActivationRequestSdkTag = "csharp/1.2.1";
        private const int ArmorLineWidth = 64;
        private const int MaxRequestHwid = 256;
        private const int MaxRequestMachineName = 128;
        private const int MaxRequestOs = 64;
        private const int MaxRequestSdk = 64;
        private const int MaxRequestLicenseKey = 64;

        private static string ClipRequestField(string value, int max) =>
            value.Length <= max ? value : value.Substring(0, max);

        private static string JsonEscapeRequest(string value)
        {
            var sb = new StringBuilder();
            sb.Append('"');
            foreach (var ch in value)
            {
                switch (ch)
                {
                    case '\\': sb.Append("\\\\"); break;
                    case '"': sb.Append("\\\""); break;
                    case '\b': sb.Append("\\b"); break;
                    case '\f': sb.Append("\\f"); break;
                    case '\n': sb.Append("\\n"); break;
                    case '\r': sb.Append("\\r"); break;
                    case '\t': sb.Append("\\t"); break;
                    default:
                        if (ch < 0x20)
                            sb.Append("\\u00").Append(((int)ch).ToString("x2", CultureInfo.InvariantCulture));
                        else
                            sb.Append(ch);
                        break;
                }
            }
            sb.Append('"');
            return sb.ToString();
        }

        private static string WrapArmor64(string value)
        {
            var lines = new List<string>();
            for (var i = 0; i < value.Length; i += ArmorLineWidth)
            {
                var len = Math.Min(ArmorLineWidth, value.Length - i);
                lines.Add(value.Substring(i, len));
            }
            return string.Join("\n", lines);
        }

        private static string DetectOsLabel()
        {
            var label = Environment.OSVersion.Platform switch
            {
                PlatformID.Win32NT => "Windows " + Environment.OSVersion.Version,
                PlatformID.Unix => "Linux",
                PlatformID.MacOSX => "macOS",
                _ => Environment.OSVersion.ToString()
            };
            return ClipRequestField(label, MaxRequestOs);
        }

        private static string CanonicalActivationRequestJson(
            string appId, string hwid, string createdAt,
            string? machineName, string? os, string? sdk, string? licenseKey)
        {
            var parts = new List<string>
            {
                $"\"v\":{ActivationRequestVersion}",
                $"\"typ\":{JsonEscapeRequest(ActivationRequestTyp)}",
                $"\"appId\":{JsonEscapeRequest(appId)}",
                $"\"hwid\":{JsonEscapeRequest(ClipRequestField(hwid, MaxRequestHwid))}",
                $"\"createdAt\":{JsonEscapeRequest(createdAt)}"
            };
            if (!string.IsNullOrEmpty(machineName))
                parts.Add($"\"machineName\":{JsonEscapeRequest(ClipRequestField(machineName, MaxRequestMachineName))}");
            if (!string.IsNullOrEmpty(os))
                parts.Add($"\"os\":{JsonEscapeRequest(ClipRequestField(os, MaxRequestOs))}");
            if (!string.IsNullOrEmpty(sdk))
                parts.Add($"\"sdk\":{JsonEscapeRequest(ClipRequestField(sdk, MaxRequestSdk))}");
            if (!string.IsNullOrEmpty(licenseKey))
                parts.Add($"\"licenseKey\":{JsonEscapeRequest(ClipRequestField(licenseKey, MaxRequestLicenseKey))}");
            return "{" + string.Join(",", parts) + "}";
        }

        /// <summary>Armored <c>.authforge-request</c> text from explicit fields.</summary>
        public static string FormatActivationRequest(
            string appId, string hwid, string createdAt,
            string? machineName = null, string? os = null, string? sdk = null, string? licenseKey = null)
        {
            var json = CanonicalActivationRequestJson(appId, hwid, createdAt, machineName, os, sdk, licenseKey);
            var payloadB64 = Convert.ToBase64String(Encoding.UTF8.GetBytes(json));
            string checksum;
            using (var sha = SHA256.Create())
            {
                var hash = sha.ComputeHash(Encoding.UTF8.GetBytes(payloadB64));
                var hex = new StringBuilder(hash.Length * 2);
                foreach (var b in hash)
                    hex.Append(b.ToString("x2", CultureInfo.InvariantCulture));
                checksum = hex.ToString().Substring(0, 16);
            }
            var clean = appId.Replace("\r", " ").Replace("\n", " ").Trim();
            return string.Join("\n", new[]
            {
                BeginActivationRequest,
                $"Version: {ActivationRequestVersion}",
                "App-Id: " + clean,
                "Checksum: " + checksum,
                "",
                WrapArmor64(payloadB64),
                EndActivationRequest,
                ""
            });
        }

        /// <summary>
        /// Build an activation request (<c>.authforge-request</c>) for this machine.
        /// No network, no session, no app secret. <c>machineName</c> is omitted
        /// unless <see cref="ActivationRequestOptions.IncludeMachineName"/> is true.
        /// </summary>
        public string CreateActivationRequest(ActivationRequestOptions? options = null)
        {
            var opts = options ?? new ActivationRequestOptions();
            var createdAt = string.IsNullOrEmpty(opts.CreatedAt)
                ? DateTime.UtcNow.ToString("yyyy-MM-ddTHH:mm:ss.fff", CultureInfo.InvariantCulture) + "Z"
                : opts.CreatedAt;
            string? machineName = null;
            if (opts.IncludeMachineName)
                machineName = string.IsNullOrEmpty(opts.MachineName) ? Environment.MachineName : opts.MachineName;
            string? os = opts.OmitOs ? null : (string.IsNullOrEmpty(opts.Os) ? DetectOsLabel() : opts.Os);
            string? sdk = opts.OmitSdk ? null : (string.IsNullOrEmpty(opts.Sdk) ? ActivationRequestSdkTag : opts.Sdk);
            string? licenseKey = opts.LicenseKey ?? _licenseKey;
            return FormatActivationRequest(AppId, _hwid, createdAt!, machineName, os, sdk, licenseKey);
        }

        /// <summary>
        /// Authorize from a cloud-minted offline license file (<c>.authforge</c>)
        /// with NO network access. Accepts a filesystem path or the armored text.
        ///
        /// On success the client is authenticated (<see cref="IsAuthenticated"/>,
        /// <see cref="GetSessionData"/>, <see cref="GetAppVariables"/>,
        /// <see cref="GetLicenseVariables"/> work) and <see cref="GetOfflineLicense"/>
        /// describes the file. No grace-period thread and no online check-ins are
        /// started - the file's own <c>expiresAt</c> is the only clock. Online
        /// <see cref="Login"/> is untouched.
        ///
        /// Failures are reported through <c>OnFailure("offline_login_failed", ex)</c>
        /// and return <c>false</c>; unlike <see cref="Login"/> this never calls
        /// <see cref="Environment.Exit"/>.
        /// </summary>
        public bool LoginFromFile(string pathOrText)
        {
            string text;
            try
            {
                text = ReadLicenseFileInput(pathOrText);
            }
            catch (Exception ex)
            {
                FailSoft("offline_login_failed", ex);
                return false;
            }

            var result = VerifyLicenseFile(text, AppId, PublicKeys, _hwid);
            if (!result.Ok)
            {
                FailSoft("offline_login_failed", new ArgumentException(result.Error ?? "unknown_error"));
                return false;
            }

            ApplyOfflineLicense(result);
            return true;
        }

        /// <summary>
        /// Verify a <c>.authforge</c> file (filesystem path or armored text) with
        /// this client's app id, public key(s) and HWID, without touching session
        /// state. Never throws for bad input.
        /// </summary>
        public VerifyLicenseFileResult VerifyLicenseFile(string pathOrText, DateTimeOffset? now = null)
        {
            string text;
            try
            {
                text = ReadLicenseFileInput(pathOrText);
            }
            catch (Exception ex)
            {
                return VerifyLicenseFileResult.Failure("read_error: " + ex.Message);
            }

            return VerifyLicenseFile(text, AppId, PublicKeys, _hwid, now);
        }

        /// <summary>Details of the offline file the client authenticated with, or <c>null</c>.</summary>
        public OfflineLicense? GetOfflineLicense()
        {
            lock (_lock)
            {
                return _offlineLicense;
            }
        }

        /// <summary>
        /// Parse armored <c>.authforge</c> text into headers, the canonical base64
        /// payload string and the base64 signature. Returns <c>null</c> when the
        /// armor is malformed. Tolerates CRLF, a UTF-8 BOM, any re-wrapping of the
        /// base64 body and text before/after the armor.
        /// </summary>
        public static ParsedLicenseFile? ParseLicenseFile(string text)
        {
            if (text is null)
            {
                return null;
            }

            var normalized = text.TrimStart('\uFEFF').Replace("\r\n", "\n").Replace('\r', '\n');
            var lines = normalized.Split('\n');

            int Find(string marker, int start)
            {
                for (var i = start; i < lines.Length; i++)
                {
                    if (lines[i].Trim() == marker)
                    {
                        return i;
                    }
                }
                return -1;
            }

            var beginIdx = Find(OfflineBeginLicense, 0);
            if (beginIdx == -1) return null;
            var endIdx = Find(OfflineEndLicense, beginIdx + 1);
            if (endIdx == -1) return null;
            var sigBeginIdx = Find(OfflineBeginSignature, endIdx + 1);
            if (sigBeginIdx == -1) return null;
            var sigEndIdx = Find(OfflineEndSignature, sigBeginIdx + 1);
            if (sigEndIdx == -1) return null;

            var block = lines.Skip(beginIdx + 1).Take(endIdx - beginIdx - 1).ToArray();
            var blankIdx = Array.FindIndex(block, line => line.Trim().Length == 0);
            if (blankIdx == -1) return null;

            var headers = new Dictionary<string, string>(StringComparer.Ordinal);
            foreach (var raw in block.Take(blankIdx))
            {
                var line = raw.Trim();
                var colon = line.IndexOf(':');
                if (colon <= 0) return null;
                headers[line.Substring(0, colon).Trim()] = line.Substring(colon + 1).Trim();
            }

            var payloadBase64 = WhitespaceRegex.Replace(string.Concat(block.Skip(blankIdx + 1)), string.Empty);
            var signatureBase64 = WhitespaceRegex.Replace(
                string.Concat(lines.Skip(sigBeginIdx + 1).Take(sigEndIdx - sigBeginIdx - 1)),
                string.Empty);
            if (payloadBase64.Length == 0 || !OfflineBase64Regex.IsMatch(payloadBase64)) return null;
            if (signatureBase64.Length == 0 || !OfflineBase64Regex.IsMatch(signatureBase64)) return null;

            return new ParsedLicenseFile(headers, payloadBase64, signatureBase64);
        }

        /// <summary>
        /// Verify armored <c>.authforge</c> text with NO network access. Check
        /// order (fixed across every SDK): <c>bad_armor</c> -&gt; <c>bad_signature</c>
        /// -&gt; <c>unsupported_version</c> -&gt; <c>malformed_payload</c> -&gt;
        /// <c>wrong_app</c> -&gt; <c>expired</c> -&gt; <c>hwid_mismatch</c>. The
        /// signature is checked before the payload JSON is decoded.
        /// </summary>
        /// <param name="file">Armored file text.</param>
        /// <param name="appId">Your app id; must equal the payload appId.</param>
        /// <param name="publicKeys">Trusted raw-32-byte Ed25519 keys (standard base64). Comma-separated entries are split.</param>
        /// <param name="hwid">Local HWID (required for bound files).</param>
        /// <param name="now">Clock override (tests).</param>
        public static VerifyLicenseFileResult VerifyLicenseFile(
            string file,
            string appId,
            IEnumerable<string> publicKeys,
            string? hwid,
            DateTimeOffset? now = null)
        {
            var parsed = ParseLicenseFile(file);
            if (parsed is null)
            {
                return VerifyLicenseFileResult.Failure("bad_armor");
            }

            var keys = (publicKeys ?? Array.Empty<string>())
                .Where(k => k != null)
                .SelectMany(k => k.Split(','))
                .Select(k => k.Trim())
                .Where(k => k.Length > 0)
                .ToList();
            if (!VerifyOfflineSignature(parsed.PayloadBase64, parsed.SignatureBase64, keys))
            {
                return VerifyLicenseFileResult.Failure("bad_signature");
            }

            JsonDocument doc;
            try
            {
                doc = JsonDocument.Parse(Convert.FromBase64String(parsed.PayloadBase64));
            }
            catch
            {
                return VerifyLicenseFileResult.Failure("malformed_payload");
            }

            using (doc)
            {
                var root = doc.RootElement;
                if (root.ValueKind != JsonValueKind.Object)
                {
                    return VerifyLicenseFileResult.Failure("malformed_payload");
                }
                if (!root.TryGetProperty("v", out var versionElement)
                    || versionElement.ValueKind != JsonValueKind.Number
                    || !versionElement.TryGetInt64(out var version)
                    || version != OfflineLicenseFileVersion)
                {
                    return VerifyLicenseFileResult.Failure("unsupported_version");
                }

                if (!TryString(root, "typ", out var typ) || typ != "authforge-license")
                {
                    return VerifyLicenseFileResult.Failure("malformed_payload");
                }
                if (!TryString(root, "appId", out var payloadAppId)
                    || !TryString(root, "licenseKey", out var licenseKey)
                    || !TryString(root, "jti", out var jti)
                    || !TryString(root, "kid", out var kid)
                    || !TryString(root, "issuedAt", out var issuedAt))
                {
                    return VerifyLicenseFileResult.Failure("malformed_payload");
                }

                if (!root.TryGetProperty("expiresAt", out var expiresElement))
                {
                    return VerifyLicenseFileResult.Failure("malformed_payload");
                }
                string? expiresAt;
                if (expiresElement.ValueKind == JsonValueKind.Null)
                {
                    expiresAt = null;
                }
                else if (expiresElement.ValueKind == JsonValueKind.String && expiresElement.GetString()!.Length > 0)
                {
                    expiresAt = expiresElement.GetString();
                }
                else
                {
                    return VerifyLicenseFileResult.Failure("malformed_payload");
                }

                if (!root.TryGetProperty("hwid", out var hwidElement) || hwidElement.ValueKind != JsonValueKind.Object
                    || !TryString(hwidElement, "mode", out var mode))
                {
                    return VerifyLicenseFileResult.Failure("malformed_payload");
                }
                OfflineHwidPolicy policy;
                if (mode == "bound")
                {
                    if (!hwidElement.TryGetProperty("hwids", out var hwidsElement) || hwidsElement.ValueKind != JsonValueKind.Array)
                    {
                        return VerifyLicenseFileResult.Failure("malformed_payload");
                    }
                    var list = new List<string>();
                    foreach (var entry in hwidsElement.EnumerateArray())
                    {
                        if (entry.ValueKind != JsonValueKind.String || string.IsNullOrEmpty(entry.GetString()))
                        {
                            return VerifyLicenseFileResult.Failure("malformed_payload");
                        }
                        list.Add(entry.GetString()!);
                    }
                    if (list.Count == 0)
                    {
                        return VerifyLicenseFileResult.Failure("malformed_payload");
                    }
                    policy = OfflineHwidPolicy.Bound(list);
                }
                else if (mode == "any")
                {
                    policy = OfflineHwidPolicy.Any();
                }
                else
                {
                    return VerifyLicenseFileResult.Failure("malformed_payload");
                }

                if (payloadAppId != (appId ?? string.Empty).Trim())
                {
                    return VerifyLicenseFileResult.Failure("wrong_app");
                }

                var nowValue = now ?? DateTimeOffset.UtcNow;
                if (expiresAt != null)
                {
                    if (!DateTimeOffset.TryParse(expiresAt, CultureInfo.InvariantCulture, DateTimeStyles.AssumeUniversal | DateTimeStyles.AdjustToUniversal, out var exp)
                        || exp <= nowValue)
                    {
                        return VerifyLicenseFileResult.Failure("expired");
                    }
                }

                if (policy.Mode == "bound")
                {
                    var local = (hwid ?? string.Empty).Trim();
                    if (local.Length == 0 || !policy.Hwids.Contains(local, StringComparer.Ordinal))
                    {
                        return VerifyLicenseFileResult.Failure("hwid_mismatch");
                    }
                }

                var license = new OfflineLicense
                {
                    AppId = payloadAppId,
                    LicenseKey = licenseKey,
                    Jti = jti,
                    KeyId = kid,
                    IssuedAt = issuedAt,
                    ExpiresAt = expiresAt,
                    HwidPolicy = policy,
                    Label = TryString(root, "label", out var label) ? label : null,
                    LicenseExpirationPresent = root.TryGetProperty("licenseExpiresAt", out var licenseExpElement),
                    LicenseExpiresAt = root.TryGetProperty("licenseExpiresAt", out licenseExpElement) && licenseExpElement.ValueKind == JsonValueKind.String
                        ? licenseExpElement.GetString()
                        : null,
                    LicenseVariables = root.TryGetProperty("licenseVariables", out var lv) ? ConvertJsonElementObject(lv) : null,
                    AppVariables = root.TryGetProperty("appVariables", out var av) ? ConvertJsonElementObject(av) : null,
                    Payload = ConvertJsonElementObject(root) ?? new Dictionary<string, object?>(StringComparer.Ordinal),
                    PayloadBase64 = parsed.PayloadBase64,
                    SignatureBase64 = parsed.SignatureBase64,
                };
                return VerifyLicenseFileResult.Success(license);
            }
        }

        private static bool TryString(JsonElement obj, string name, out string value)
        {
            value = string.Empty;
            if (!obj.TryGetProperty(name, out var element) || element.ValueKind != JsonValueKind.String)
            {
                return false;
            }
            var text = element.GetString();
            if (string.IsNullOrEmpty(text))
            {
                return false;
            }
            value = text!;
            return true;
        }

        private static bool VerifyOfflineSignature(string payloadBase64, string signatureBase64, IReadOnlyList<string> keys)
        {
            byte[] signatureBytes;
            try
            {
                signatureBytes = Convert.FromBase64String(signatureBase64);
            }
            catch (FormatException)
            {
                return false;
            }
            if (signatureBytes.Length != 64)
            {
                return false;
            }

            var message = Encoding.UTF8.GetBytes(payloadBase64);
            foreach (var keyB64 in keys)
            {
                try
                {
                    var raw = Convert.FromBase64String(keyB64);
                    if (raw.Length != 32)
                    {
                        continue;
                    }
                    var verifier = new Ed25519Signer();
                    verifier.Init(forSigning: false, new Ed25519PublicKeyParameters(raw, 0));
                    verifier.BlockUpdate(message, 0, message.Length);
                    if (verifier.VerifySignature(signatureBytes))
                    {
                        return true;
                    }
                }
                catch
                {
                    // Malformed key - try the next one.
                }
            }
            return false;
        }

        private static string ReadLicenseFileInput(string pathOrText)
        {
            if (string.IsNullOrEmpty(pathOrText))
            {
                throw new ArgumentException("license file must be a path or the armored text");
            }
            if (pathOrText.Contains(OfflineBeginLicense))
            {
                return pathOrText;
            }
            return File.ReadAllText(pathOrText, Encoding.UTF8);
        }

        private void ApplyOfflineLicense(VerifyLicenseFileResult result)
        {
            // Stop any online session first so the two modes never overlap.
            Logout();
            var license = result.License!;
            long? expiresIn = null;
            if (license.ExpiresAt != null
                && DateTimeOffset.TryParse(license.ExpiresAt, CultureInfo.InvariantCulture, DateTimeStyles.AssumeUniversal | DateTimeStyles.AdjustToUniversal, out var exp))
            {
                expiresIn = exp.ToUnixTimeSeconds();
            }

            lock (_lock)
            {
                _licenseKey = license.LicenseKey;
                // Offline files carry no server session token.
                _sessionToken = null;
                _sessionKind = SessionKind.Offline;
                _sessionExpiresIn = expiresIn;
                _rawPayloadB64 = license.PayloadBase64;
                _signature = license.SignatureBase64;
                _keyId = license.KeyId;
                _sessionData = new Dictionary<string, object?>(license.Payload, StringComparer.Ordinal);
                _appVariables = license.AppVariables;
                _licenseVariables = license.LicenseVariables;
                _offlineLicense = license;
                _authenticated = true;
            }
        }

        private void FailSoft(string reason, Exception? ex)
        {
            if (OnFailure is null)
            {
                return;
            }
            try
            {
                OnFailure(reason, ex);
            }
            catch
            {
                // Caller's callback threw; nothing else to do offline.
            }
        }
    }

    /// <summary>HWID binding policy embedded in a <c>.authforge</c> file.</summary>
    public sealed class OfflineHwidPolicy
    {
        private OfflineHwidPolicy(string mode, IReadOnlyList<string> hwids)
        {
            Mode = mode;
            Hwids = hwids;
        }

        /// <summary><c>"bound"</c> or <c>"any"</c>.</summary>
        public string Mode { get; }
        /// <summary>Allowed HWIDs when <see cref="Mode"/> is <c>"bound"</c>; empty otherwise.</summary>
        public IReadOnlyList<string> Hwids { get; }

        public static OfflineHwidPolicy Bound(IReadOnlyList<string> hwids) => new OfflineHwidPolicy("bound", hwids);
        public static OfflineHwidPolicy Any() => new OfflineHwidPolicy("any", Array.Empty<string>());
    }

    /// <summary>Verified content of a <c>.authforge</c> file.</summary>
    public sealed class OfflineLicense
    {
        public string AppId { get; set; } = string.Empty;
        public string LicenseKey { get; set; } = string.Empty;
        /// <summary>Unique id of this minted file.</summary>
        public string Jti { get; set; } = string.Empty;
        /// <summary>App signing key id that signed the file.</summary>
        public string KeyId { get; set; } = string.Empty;
        public string IssuedAt { get; set; } = string.Empty;
        /// <summary>ISO 8601 file expiry, or <c>null</c> for a lifetime file.</summary>
        public string? ExpiresAt { get; set; }
        public OfflineHwidPolicy HwidPolicy { get; set; } = OfflineHwidPolicy.Any();
        public string? Label { get; set; }
        /// <summary>True when the payload carried <c>licenseExpiresAt</c> (lifetime licenses use JSON null).</summary>
        public bool LicenseExpirationPresent { get; set; }
        public string? LicenseExpiresAt { get; set; }
        public Dictionary<string, object?>? LicenseVariables { get; set; }
        public Dictionary<string, object?>? AppVariables { get; set; }
        /// <summary>Full decoded payload (unknown fields preserved).</summary>
        public Dictionary<string, object?> Payload { get; set; } = new Dictionary<string, object?>(StringComparer.Ordinal);
        /// <summary>Canonical signed string and its signature.</summary>
        public string PayloadBase64 { get; set; } = string.Empty;
        public string SignatureBase64 { get; set; } = string.Empty;
    }

    /// <summary>Raw armor split into parts.</summary>
    public sealed class ParsedLicenseFile
    {
        public ParsedLicenseFile(IReadOnlyDictionary<string, string> headers, string payloadBase64, string signatureBase64)
        {
            Headers = headers;
            PayloadBase64 = payloadBase64;
            SignatureBase64 = signatureBase64;
        }

        public IReadOnlyDictionary<string, string> Headers { get; }
        /// <summary>Exactly the string the signature covers.</summary>
        public string PayloadBase64 { get; }
        public string SignatureBase64 { get; }
    }

    /// <summary>Result of <see cref="AuthForgeClient.VerifyLicenseFile(string, string, IEnumerable{string}, string?, DateTimeOffset?)"/>.</summary>
    public sealed class VerifyLicenseFileResult
    {
        private VerifyLicenseFileResult(bool ok, string? error, OfflineLicense? license)
        {
            Ok = ok;
            Error = error;
            License = license;
        }

        public bool Ok { get; }
        /// <summary>
        /// Cross-SDK error code when <see cref="Ok"/> is false: <c>bad_armor</c>,
        /// <c>bad_signature</c>, <c>unsupported_version</c>, <c>malformed_payload</c>,
        /// <c>wrong_app</c>, <c>expired</c>, <c>hwid_mismatch</c> (or <c>read_error: …</c>).
        /// </summary>
        public string? Error { get; }
        public OfflineLicense? License { get; }

        internal static VerifyLicenseFileResult Success(OfflineLicense license) => new VerifyLicenseFileResult(true, null, license);
        internal static VerifyLicenseFileResult Failure(string error) => new VerifyLicenseFileResult(false, error, null);
    }
}
