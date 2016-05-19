using System.Collections.Generic;

namespace Jwt
{
    /// <summary>
    /// Represents a JSON Web Token.
    /// </summary>
    public class JwtData
    {
        /// <summary>
        /// Gets or sets the bytes representing the key of the JWT.
        /// </summary>
        public byte[] KeyBytes { get; set; }

        /// <summary>
        /// Gets or sets a string representing the key of the JWT.
        /// </summary>
        public string Key { get; set; }

        /// <summary>
        /// Gets or sets the payload of the JWT.
        /// </summary>
        public object Payload { get; set; }

        /// <summary>
        /// Gets or sets the hashing algorithm being used for the JWT.
        /// </summary>
        public JwtHashAlgorithm Algorithm { get; set; } = JwtHashAlgorithm.HS256;

        /// <summary>
        /// Gets or sets a value indicating whether the payload is already serialized to JSON.
        /// </summary>
        public bool Serialized { get; set; }

        /// <summary>
        /// Gets or sets a dictionary of extra heading to append to the JWT.
        /// </summary>
        public IDictionary<string, object> ExtraHeaders { get; set; }
    }
}
