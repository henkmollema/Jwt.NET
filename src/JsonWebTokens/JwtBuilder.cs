using System.Collections.Generic;

namespace Jwt
{
    /// <summary>
    /// Builder for <see cref="JwtData"/> objects.
    /// </summary>
    public class JwtBuilder
    {
        private readonly JwtData _data = new JwtData();

        /// <summary>
        /// Adds the specified payload to the JWT.
        /// </summary>
        /// <param name="payload">The payload.</param>
        /// <returns>The <see cref="JwtBuilder"/> instance.</returns>
        public JwtBuilder WithPayload(object payload)
        {
            _data.Payload = payload;
            return this;
        }

        /// <summary>
        /// Marks the specified payload as already serialized.
        /// </summary>
        /// <returns>The <see cref="JwtBuilder"/> instance.</returns>
        public JwtBuilder IsSerialized()
        {
            _data.Serialized = true;
            return this;
        }

        /// <summary>
        /// Adds the specified key string to the JWT.
        /// </summary>
        /// <param name="key">The string representation of the key.</param>
        /// <returns>The <see cref="JwtBuilder"/> instance.</returns>
        public JwtBuilder WithKey(string key)
        {
            _data.Key = key;
            return this;
        }

        /// <summary>
        /// Adds the specified key bytes to the JWT.
        /// </summary>
        /// <param name="keyBytes">The bytes representation of the key.</param>
        /// <returns>The <see cref="JwtBuilder"/> instance.</returns>
        public JwtBuilder WithKey(byte[] keyBytes)
        {
            _data.KeyBytes = keyBytes;
            return this;
        }

        /// <summary>
        /// Specifies the algorithm being used for hashing the JWT.
        /// </summary>
        /// <param name="algorithm">The algorithm being used for hashing the JWT.</param>
        /// <returns>The <see cref="JwtBuilder"/> instance.</returns>
        public JwtBuilder WithAlgorithm(JwtHashAlgorithm algorithm)
        {
            _data.Algorithm = algorithm;
            return this;
        }

        /// <summary>
        /// Adds the specified key/value pair as header to the JWT.
        /// </summary>
        /// <param name="key">The key of the key/value pair.</param>
        /// <param name="value">The value of the key/value pair.</param>
        /// <returns>The <see cref="JwtBuilder"/> instance.</returns>
        public JwtBuilder WithHeader(string key, object value)
        {
            if (_data.ExtraHeaders == null)
            {
                _data.ExtraHeaders = new Dictionary<string, object>();
            }

            _data.ExtraHeaders.Add(key, value);
            return this;
        }

        /// <summary>
        /// Adds the specified dictionary as headers to the JWT.
        /// </summary>
        /// <param name="dict">The dictionary with the headers of the JWT.</param>
        /// <returns>The <see cref="JwtBuilder"/> instance.</returns>
        public JwtBuilder WithHeaders(IDictionary<string, object> dict)
        {
            _data.ExtraHeaders = dict;
            return this;
        }

        /// <summary>
        /// Builds the data to a <see cref="JwtData"/> object.
        /// </summary>
        /// <returns>A <see cref="JwtData"/> object.</returns>
        public JwtData Build() => _data;

        /// <summary>
        /// Builds and encodes the current <see cref="JwtBuilder"/> object.
        /// </summary>
        /// <returns>An encoded JSON Web Token.</returns>
        public string Encode() => JsonWebToken.Encode(Build());
    }
}
