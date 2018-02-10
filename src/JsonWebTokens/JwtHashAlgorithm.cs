namespace Jwt
{
    /// <summary>
    /// Specifies the hashing algorithm being used used.
    /// </summary>
    public enum JwtHashAlgorithm
    {
        /// <summary>
        /// Hash-based Message Authentication Code (HMAC) using SHA256.
        /// </summary>
        HS256,

        /// <summary>
        /// Hash-based Message Authentication Code (HMAC) using SHA384.
        /// </summary>
        HS384,

        /// <summary>
        /// Hash-based Message Authentication Code (HMAC) using SHA512.
        /// </summary>
        HS512
    }
}
