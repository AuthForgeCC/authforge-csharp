using System;

namespace AuthForge
{
    /// <summary>
    /// A failure with a machine-readable <see cref="Code"/>: the server's error
    /// code (<c>revoked</c>, <c>hwid_mismatch</c>, ...) or an SDK code
    /// (<c>network_error</c>, <c>timeout</c>, <c>http_error_502</c>,
    /// <c>unexpected_response</c>, ...). For server errors <see cref="Exception.Message"/>
    /// equals <see cref="Code"/>; network failures keep the <c>url_error: ...</c> message.
    /// </summary>
    public sealed class AuthForgeException : Exception
    {
        public AuthForgeException(string code, string? message = null, Exception? innerException = null)
            : base(message ?? code, innerException)
        {
            Code = code ?? throw new ArgumentNullException(nameof(code));
        }

        public string Code { get; }

        /// <summary>True when AuthForge gave no verdict on the session, so a later check-in can succeed.</summary>
        public bool IsTransient => AuthForgeClient.IsTransientError(Code);

        /// <summary>True when AuthForge definitively rejected the session or license.</summary>
        public bool IsFatal => !IsTransient;
    }
}
