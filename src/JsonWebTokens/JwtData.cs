using System.Collections.Generic;

namespace Jwt
{
    public class JwtData
    {
        public byte[] KeyBytes { get; set; }

        public string Key { get; set; }

        public object Payload { get; set; }

        public JwtHashAlgorithm Algorithm { get; set; } = JwtHashAlgorithm.HS256;

        /// <summary>
        /// Gets or sets a value whether the payload is already serialized to JSON.
        /// </summary>
        public bool Serialized { get; set; }

        public IDictionary<string, object> ExtraHeaders { get; set; }
    }

    public class JwtBuilder
    {
        private readonly JwtData _data = new JwtData();

        public JwtBuilder WithPayload(object payload)
        {
            _data.Payload = payload;
            return this;
        }

        public JwtBuilder IsSerialized()
        {
            _data.Serialized = true;
            return this;
        }

        public JwtBuilder WithKey(string key)
        {
            _data.Key = key;
            return this;
        }

        public JwtBuilder WithKey(byte[] keyBytes)
        {
            _data.KeyBytes = keyBytes;
            return this;
        }

        public JwtBuilder WithAlgorithm(JwtHashAlgorithm algorithm)
        {
            _data.Algorithm = algorithm;
            return this;
        }

        public JwtBuilder WithHeader(string key, object value)
        {
            if (_data.ExtraHeaders == null)
            {
                _data.ExtraHeaders = new Dictionary<string, object>();
            }

            _data.ExtraHeaders.Add(key, value);
            return this;
        }

        public JwtBuilder WithHeaders(IDictionary<string, object> dict)
        {
            _data.ExtraHeaders = dict;
            return this;
        }

        /// <summary>
        /// Builds the data to a <see cref="JwtData"/> object.
        /// </summary>
        /// <returns>A <see cref="JwtData"/> object.</returns>
        public JwtData Build()
        {
            return _data;
        }
    }
}
