using System;
using System.Collections.Generic;
using System.IO;
using System.Text;
using System.Text.Json;

namespace AuthForge
{
    /// <summary>
    /// Self-serve offline activation: one online call to
    /// <c>/auth/offline/activate</c> turns a license key into a lifetime,
    /// HWID-bound <c>.authforge</c> file. After that the app runs from the
    /// file with <see cref="LoginFromFile"/> and no network.
    ///
    /// This is separate from air-gapped offline files (minted by the operator,
    /// no App Secret on the machine): activation is an online call and needs
    /// the App Secret.
    /// </summary>
    public sealed partial class AuthForgeClient
    {
        private const string OfflineActivatePath = "/auth/offline/activate";

        /// <summary>
        /// <c>replay</c> from the last successful <see cref="ActivateOffline"/>
        /// response (<c>true</c> when the server returned the file this machine
        /// already had); <c>null</c> before the first success. Test hook.
        /// </summary>
        internal bool? LastOfflineActivationReplay { get; private set; }

        /// <summary>
        /// Exchange a license key for a lifetime, HWID-bound offline license
        /// file in one online call, then authenticate from it exactly as
        /// <see cref="LoginFromFile"/> does (offline session, variables,
        /// <see cref="GetOfflineLicense"/>, no background thread).
        ///
        /// The returned file is verified locally (signature against
        /// <see cref="PublicKeys"/>, <see cref="AppId"/>, this machine's HWID)
        /// before anything is written. When <paramref name="path"/> is set the
        /// file is written there byte-for-byte and atomically (temp file in the
        /// same directory, then rename), creating parent directories.
        ///
        /// A new machine costs the app owner 2 credits; activating a machine
        /// that already has a file returns the identical file for free.
        ///
        /// Failures throw <see cref="AuthForgeException"/> with the server code
        /// (<c>offline_activation_disabled</c>, <c>offline_activation_requires_perpetual</c>,
        /// <c>offline_activation_requires_seats</c>, <c>offline_activation_limit_reached</c>,
        /// <c>hwid_mismatch</c> (no free seat), <c>invalid_key</c>, <c>revoked</c>, ...)
        /// or an SDK code (<c>offline_file_rejected</c>, <c>file_write_failed</c>,
        /// <c>unexpected_response</c>, <c>network_error</c>, <c>timeout</c>, ...).
        /// On failure nothing is written to <paramref name="path"/>, the client is
        /// not authenticated (an existing session is left as it was), and neither <see cref="OnFailure"/> nor
        /// <see cref="Environment.Exit"/> is called.
        /// </summary>
        /// <param name="licenseKey">The license key the buyer entered.</param>
        /// <param name="path">Where to save the <c>.authforge</c> file; <c>null</c> to skip writing.</param>
        /// <returns><c>true</c> on success.</returns>
        /// <exception cref="ArgumentException"><paramref name="licenseKey"/> is empty, or the client has no App Secret.</exception>
        /// <exception cref="AuthForgeException">The activation was refused or failed.</exception>
        public bool ActivateOffline(string licenseKey, string? path = null)
        {
            if (string.IsNullOrEmpty(licenseKey))
            {
                throw new ArgumentException("license_key must be a non-empty string", nameof(licenseKey));
            }
            RequireAppSecret();

            try
            {
                var result = RequestOfflineActivation(licenseKey, out var replay);
                if (!string.IsNullOrEmpty(path))
                {
                    WriteFileAtomic(path!, result.File);
                }
                ApplyOfflineLicense(result.Verified);
                LastOfflineActivationReplay = replay;
                return true;
            }
            catch (AuthForgeException)
            {
                // A failed activation authenticates nothing and leaves any
                // existing session as it was.
                LastOfflineActivationReplay = null;
                throw;
            }
        }

        private (string File, VerifyLicenseFileResult Verified) RequestOfflineActivation(string licenseKey, out bool replay)
        {
            var body = new Dictionary<string, object?>
            {
                ["appId"] = AppId,
                ["appSecret"] = AppSecret,
                ["licenseKey"] = licenseKey,
                ["hwid"] = _hwid,
                ["nonce"] = GenerateNonce(),
            };

            Dictionary<string, JsonElement> responseObj;
            try
            {
                // skipFailureOnNetwork: errors are thrown to the caller, never
                // routed to OnFailure / Environment.Exit.
                responseObj = PostJson(OfflineActivatePath, body, skipFailureOnNetwork: true);
            }
            catch (ArgumentException ex)
            {
                // invalid_json_response / response_not_json_object on a 2xx body.
                throw new AuthForgeException("unexpected_response", "unexpected_response: " + ex.Message, ex);
            }

            responseObj.TryGetValue("status", out var statusElement);
            if (!IsSuccessStatus(statusElement))
            {
                // {"status":"failed","error":"<code>"} -> that code; anything else -> unexpected_response.
                throw HeartbeatRejection(responseObj);
            }

            if (!responseObj.TryGetValue("file", out var fileElement)
                || fileElement.ValueKind != JsonValueKind.String
                || string.IsNullOrEmpty(fileElement.GetString()))
            {
                throw new AuthForgeException(
                    "unexpected_response",
                    $"unexpected_response: success without file (file={DescribeJson(fileElement)})");
            }
            var file = fileElement.GetString()!;

            // The server's hwid_mismatch means "no free seat"; a file that fails
            // local checks is always offline_file_rejected, with the verifier's
            // reason in the message.
            var verified = VerifyLicenseFile(file, AppId, PublicKeys, _hwid);
            if (!verified.Ok)
            {
                var reason = verified.Error ?? "unknown_error";
                throw new AuthForgeException("offline_file_rejected", "offline_file_rejected: " + reason);
            }

            replay = responseObj.TryGetValue("replay", out var replayElement)
                && replayElement.ValueKind == JsonValueKind.True;
            return (file, verified);
        }

        /// <summary>
        /// Writes <paramref name="contents"/> as UTF-8 (no BOM, no newline
        /// changes) to a temp file next to <paramref name="path"/> and renames it
        /// over the target, so the target is either untouched or complete.
        /// </summary>
        private static void WriteFileAtomic(string path, string contents)
        {
            string tempPath = string.Empty;
            try
            {
                var fullPath = Path.GetFullPath(path);
                var directory = Path.GetDirectoryName(fullPath);
                if (!string.IsNullOrEmpty(directory))
                {
                    Directory.CreateDirectory(directory);
                }

                var bytes = new UTF8Encoding(encoderShouldEmitUTF8Identifier: false).GetBytes(contents);
                tempPath = Path.Combine(
                    directory ?? string.Empty,
                    "." + Path.GetFileName(fullPath) + "." + Guid.NewGuid().ToString("N") + ".tmp");
                using (var stream = new FileStream(tempPath, FileMode.CreateNew, FileAccess.Write, FileShare.None))
                {
                    stream.Write(bytes, 0, bytes.Length);
                    stream.Flush(flushToDisk: true);
                }

#if NETCOREAPP3_0_OR_GREATER
                File.Move(tempPath, fullPath, overwrite: true);
#else
                if (File.Exists(fullPath))
                {
                    File.Replace(tempPath, fullPath, null);
                }
                else
                {
                    File.Move(tempPath, fullPath);
                }
#endif
                tempPath = string.Empty;
            }
            catch (Exception ex) when (ex is IOException || ex is UnauthorizedAccessException || ex is NotSupportedException || ex is ArgumentException || ex is System.Security.SecurityException)
            {
                throw new AuthForgeException(
                    "file_write_failed",
                    "file_write_failed: " + ex.Message + " (the machine is activated; activating again returns the same file for free)",
                    ex);
            }
            finally
            {
                if (tempPath.Length > 0)
                {
                    try
                    {
                        File.Delete(tempPath);
                    }
                    catch
                    {
                        // Best effort cleanup of the temp file.
                    }
                }
            }
        }
    }
}
