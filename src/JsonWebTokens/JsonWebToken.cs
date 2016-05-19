using System;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Text;

namespace Jwt
{
    /// <summary>
    /// Provides methods for encoding and decoding JSON Web Tokens.
    /// </summary>
    public static class JsonWebToken
    {
        /// <summary>
        /// Gets or sets the <see cref="IJsonSerializer"/> implementation being used.
        /// </summary>
        public static IJsonSerializer JsonSerializer = new DefaultJsonSerializer();

        private static readonly DateTime UnixEpoch = new DateTime(1970, 1, 1, 0, 0, 0, 0, DateTimeKind.Utc);

        /// <summary>
        /// Creates a JWT using the specified payload, key and algorithm.
        /// </summary>
        /// <param name="payload">An arbitrary payload (must be serializable to JSON).</param>
        /// <param name="key">The key bytes used to sign the token.</param>
        /// <param name="algorithm">The hash algorithm to use.</param>
        /// <returns>The generated JWT.</returns>
        public static string Encode(object payload, byte[] key, JwtHashAlgorithm algorithm)
        {
            return Encode(new JwtData { Payload = payload, KeyBytes = key, Algorithm = algorithm });
        }

        /// <summary>
        /// Creates a JWT using the specified payload, key and algorithm.
        /// </summary>
        /// <param name="payload">An arbitrary payload (must be serializable to JSON).</param>
        /// <param name="key">The key used to sign the token.</param>
        /// <param name="algorithm">The hash algorithm to use.</param>
        /// <returns>The generated JWT.</returns>
        public static string Encode(object payload, string key, JwtHashAlgorithm algorithm)
        {
            return Encode(new JwtData { Payload = payload, Key = key, Algorithm = algorithm });
        }

        /// <summary>
        /// Creates a JWT using the specified <see cref="JwtData"/>.
        /// </summary>
        /// <param name="data">A <see cref="JwtData"/> object.</param>
        /// <returns>The generated JWT.</returns>
        public static string Encode(JwtData data)
        {
            var header = new Dictionary<string, object>(data.ExtraHeaders ?? new Dictionary<string, object>())
                         {
                             { "typ", "JWT" },
                             { "alg", data.Algorithm.ToString() }
                         };

            var headerBytes = Encoding.UTF8.GetBytes(JsonSerializer.Serialize(header));
            var payloadBytes = Encoding.UTF8.GetBytes(data.Serialized ? (string)data.Payload : JsonSerializer.Serialize(data.Payload));

            var segments = new List<string>
                           {
                               Base64UrlEncode(headerBytes),
                               Base64UrlEncode(payloadBytes)
                           };

            var bytesToSign = Encoding.UTF8.GetBytes(string.Join(".", segments));

            var keyBytes = data.KeyBytes;
            if (keyBytes == null || keyBytes.Length == 0)
            {
                keyBytes = Encoding.UTF8.GetBytes(data.Key);
            }

            var signature = ComputeHash(data.Algorithm, keyBytes, bytesToSign);
            segments.Add(Base64UrlEncode(signature));

            return string.Join(".", segments);
        }

        /// <summary>
        /// Decodes the specified JWT and returns the JSON payload.
        /// </summary>
        /// <param name="token">The JWT.</param>
        /// <param name="key">The key that was used to sign the JWT.</param>
        /// <param name="verify">Whether to verify the signature (default is true).</param>
        /// <returns>A string containing the JSON payload.</returns>
        /// <exception cref="SignatureVerificationException">
        /// If the <paramref name="verify"/> parameter was true and the signature was not valid
        /// or if the JWT was signed with an unsupported algorithm.
        /// </exception>
        /// <exception cref="ArgumentException">
        /// When the given <paramref name="token"/> doesn't consist of 3 parts delimited by dots.
        /// </exception>
        public static string Decode(string token, string key, bool verify = true)
        {
            return Decode(token, Encoding.UTF8.GetBytes(key), verify);
        }

        /// <summary>
        /// Decodes the specified JWT and returns the JSON payload.
        /// </summary>
        /// <param name="token">The JWT.</param>
        /// <param name="key">The key bytes that were used to sign the JWT.</param>
        /// <param name="verify">Whether to verify the signature (default is true).</param>
        /// <returns>A string containing the JSON payload.</returns>
        /// <exception cref="SignatureVerificationException">
        /// If the <paramref name="verify"/> parameter was true and the signature was not valid
        /// or if the JWT was signed with an unsupported algorithm.
        /// </exception>
        /// <exception cref="ArgumentException">
        /// When the given <paramref name="token"/> doesn't consist of 3 parts delimited by dots.
        /// </exception>
        public static string Decode(string token, byte[] key, bool verify = true)
        {
            var parts = token.Split('.');
            if (parts.Length != 3)
            {
                throw new ArgumentException($"Token must consist of 3 parts delimited by dot. Given token: '{token}'.");
            }

            var header = parts[0];
            var payload = parts[1];
            var crypto = Base64UrlDecode(parts[2]);

            var headerBytes = Base64UrlDecode(header);
            var headerJson = Encoding.UTF8.GetString(headerBytes, 0, headerBytes.Length);

            var payloadBytes = Base64UrlDecode(payload);
            var payloadJson = Encoding.UTF8.GetString(payloadBytes, 0, payloadBytes.Length);

            var headerData = JsonSerializer.Deserialize<IDictionary<string, object>>(headerJson);

            if (verify)
            {
                var bytesToSign = Encoding.UTF8.GetBytes(string.Concat(header, ".", payload));
                var algorithm = (string)headerData["alg"];

                var signature = ComputeHash(GetHashAlgorithm(algorithm), key, bytesToSign);
                var decodedCrypto = Convert.ToBase64String(crypto);
                var decodedSignature = Convert.ToBase64String(signature);

                Verify(decodedCrypto, decodedSignature, payloadJson);
            }

            return payloadJson;
        }

        /// <summary>
        /// Decodes the JWT token and deserializes JSON payload to an <see cref="object"/>.
        /// </summary>
        /// <param name="token">The JWT.</param>
        /// <param name="key">The key that was used to sign the JWT.</param>
        /// <param name="verify">Whether to verify the signature (default is true).</param>
        /// <returns>An object representing the payload.</returns>
        /// <exception cref="SignatureVerificationException">
        /// If the <paramref name="verify"/> parameter was true and the signature was not valid
        /// or if the JWT was signed with an unsupported algorithm.
        /// </exception>
        /// <exception cref="ArgumentException">
        /// When the given <paramref name="token"/> doesn't consist of 3 parts delimited by dots.
        /// </exception>
        public static object DecodeToObject(string token, string key, bool verify = true)
        {
            return DecodeToObject(token, Encoding.UTF8.GetBytes(key), verify);
        }

        /// <summary>
        /// Decodes the JWT token and deserializes JSON payload to an <see cref="object"/>.
        /// </summary>
        /// <param name="token">The JWT.</param>
        /// <param name="key">The key that was used to sign the JWT.</param>
        /// <param name="verify">Whether to verify the signature (default is true).</param>
        /// <returns>An object representing the payload.</returns>
        /// <exception cref="SignatureVerificationException">
        /// If the <paramref name="verify"/> parameter was true and the signature was not valid
        /// or if the JWT was signed with an unsupported algorithm.
        /// </exception>
        /// <exception cref="ArgumentException">
        /// When the given <paramref name="token"/> doesn't consist of 3 parts delimited by dots.
        /// </exception>
        public static object DecodeToObject(string token, byte[] key, bool verify = true)
        {
            var payloadJson = Decode(token, key, verify);
            var payloadData = JsonSerializer.Deserialize<Dictionary<string, object>>(payloadJson);
            return payloadData;
        }

        /// <summary>
        /// Decodes the JWT token and deserializes JSON payload to <typeparamref name="T"/>.
        /// </summary>
        /// <typeparam name="T">The type of the object.</typeparam>
        /// <param name="token">The JWT.</param>
        /// <param name="key">The key that was used to sign the JWT.</param>
        /// <param name="verify">Whether to verify the signature (default is true).</param>
        /// <returns>An object representing the payload.</returns>
        /// <exception cref="SignatureVerificationException">
        /// If the <paramref name="verify"/> parameter was true and the signature was not valid
        /// or if the JWT was signed with an unsupported algorithm.
        /// </exception>
        /// <exception cref="ArgumentException">
        /// When the given <paramref name="token"/> doesn't consist of 3 parts delimited by dots.
        /// </exception>
        public static T DecodeToObject<T>(string token, string key, bool verify = true)
        {
            return DecodeToObject<T>(token, Encoding.UTF8.GetBytes(key), verify);
        }

        /// <summary>
        /// Decodes the JWT token and deserializes JSON payload to <typeparamref name="T"/>.
        /// </summary>
        /// <typeparam name="T">The <see cref="Type"/> to return</typeparam>
        /// <param name="token">The JWT.</param>
        /// <param name="key">The key that was used to sign the JWT.</param>
        /// <param name="verify">Whether to verify the signature (default is true).</param>
        /// <returns>An object representing the payload.</returns>
        /// <exception cref="SignatureVerificationException">
        /// If the <paramref name="verify"/> parameter was true and the signature was not valid
        /// or if the JWT was signed with an unsupported algorithm.
        /// </exception>
        /// <exception cref="ArgumentException">
        /// When the given <paramref name="token"/> doesn't consist of 3 parts delimited by dots.
        /// </exception>
        public static T DecodeToObject<T>(string token, byte[] key, bool verify = true)
        {
            var payloadJson = Decode(token, key, verify);
            var payloadData = JsonSerializer.Deserialize<T>(payloadJson);
            return payloadData;
        }

        private static void Verify(string decodedCrypto, string decodedSignature, string payloadJson)
        {
            if (decodedCrypto != decodedSignature)
            {
                throw new SignatureVerificationException($"Invalid signature. Expected '{decodedCrypto}' got '{decodedSignature}'.");
            }

            // Verify exp claim: https://tools.ietf.org/html/draft-ietf-oauth-json-web-token-32#section-4.1.4
            var payloadData = JsonSerializer.Deserialize<IDictionary<string, object>>(payloadJson);
            if (payloadData.ContainsKey("exp") && payloadData["exp"] != null)
            {
                // Safely unpack a boxed int.
                int exp;
                try
                {
                    exp = Convert.ToInt32(payloadData["exp"]);
                }
                catch (Exception)
                {
                    throw new SignatureVerificationException($"Claim 'exp' must be an integer. Given claim: '{payloadData["exp"]}'.");
                }

                var secondsSinceEpoch = Math.Round((DateTime.UtcNow - UnixEpoch).TotalSeconds);
                if (secondsSinceEpoch >= exp)
                {
                    throw new SignatureVerificationException("Token has expired.");
                }
            }
        }

        private static byte[] ComputeHash(JwtHashAlgorithm algorithm, byte[] key, byte[] value)
        {
            HashAlgorithm hashAlgorithm;
            switch (algorithm)
            {
                case JwtHashAlgorithm.HS256:
                    hashAlgorithm = new HMACSHA256(key);
                    break;
                case JwtHashAlgorithm.HS384:
                    hashAlgorithm = new HMACSHA384(key);
                    break;
                case JwtHashAlgorithm.HS512:
                    hashAlgorithm = new HMACSHA512(key);
                    break;
                default:
                    throw new Exception($"Unsupported hash algorithm: '{algorithm}'.");
            }

            using (hashAlgorithm)
            {
                return hashAlgorithm.ComputeHash(value);
            }
        }

        private static JwtHashAlgorithm GetHashAlgorithm(string algorithm)
        {
            switch (algorithm)
            {
                case "HS256":
                    return JwtHashAlgorithm.HS256;
                case "HS384":
                    return JwtHashAlgorithm.HS384;
                case "HS512":
                    return JwtHashAlgorithm.HS512;
                default:
                    throw new SignatureVerificationException("Algorithm not supported.");
            }
        }

        private static string Base64UrlEncode(byte[] input)
        {
            var output = Convert.ToBase64String(input);
            output = output.Split('=')[0]; // Remove any trailing '='s
            output = output.Replace('+', '-'); // 62nd char of encoding
            output = output.Replace('/', '_'); // 63rd char of encoding
            return output;
        }

        private static byte[] Base64UrlDecode(string input)
        {
            var output = input;
            output = output.Replace('-', '+'); // 62nd char of encoding
            output = output.Replace('_', '/'); // 63rd char of encoding
            switch (output.Length % 4) // Pad with trailing '='s
            {
                case 0:
                    break; // No pad chars in this case
                case 2:
                    output += "==";
                    break; // Two pad chars
                case 3:
                    output += "=";
                    break; // One pad char
                default:
                    throw new Exception($"Illegal base64url string: '{input}'.");
            }

            var converted = Convert.FromBase64String(output);
            return converted;
        }
    }
}
