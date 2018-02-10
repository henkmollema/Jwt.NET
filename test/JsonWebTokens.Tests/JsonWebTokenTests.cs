using System;
using System.Collections.Generic;
using Xunit;

namespace Jwt.Tests
{
    public class JsonWebTokenTests
    {
        private static readonly DateTime UnixEpoch = new DateTime(1970, 1, 1, 0, 0, 0, 0, DateTimeKind.Utc);

        [Fact]
        public void EncodeHs256Token_Returns_ExpectedToken()
        {
            // Arrange
            var payload = new Dictionary<string, object>()
            {
                { "key1", 1 },
                { "key2", "the-value" }
            };
            var secretKey = "SOME_SECRET_KEY";

            // Act
            var token = JsonWebToken.Encode(payload, secretKey, JwtHashAlgorithm.HS256);
            var decoded = JsonWebToken.Decode(token, secretKey);

            // Assert
            Assert.Equal("eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJrZXkxIjoxLCJrZXkyIjoidGhlLXZhbHVlIn0.z4nWl_itwSsz1SbxEZkxCmm9MMkIKanFvgGz_gsWIJo", token);
        }

        [Fact]
        public void InvalidSignature_ThrowsException()
        {
            // Arrange
            var token = "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJrZXkxIjoxLCJrZXkyIjoidGhlLXZhbHVlIn0.nope";

            // Act & Assert
            var ex = Assert.Throws<SignatureVerificationException>(() => JsonWebToken.Decode(token, "SOME_SECRET_KEY"));
            Assert.Equal("Invalid JWT signature.", ex.Message);
        }

        [Fact]
        public void InvalidKey_ThrowsException()
        {
            // Arrange
            var token = "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJrZXkxIjoxLCJrZXkyIjoidGhlLXZhbHVlIn0.z4nWl_itwSsz1SbxEZkxCmm9MMkIKanFvgGz_gsWIJo";

            // Act & Assert
            var ex = Assert.Throws<SignatureVerificationException>(() => JsonWebToken.Decode(token, "invalid_key"));
            Assert.Equal("Invalid JWT signature.", ex.Message);
        }

        [Fact]
        public void InvalidSignature_WithoutVerify_ReturnsPayload()
        {
            // Arrange
            var token = "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJrZXkxIjoxLCJrZXkyIjoidGhlLXZhbHVlIn0.nope";

            // Act
            var jwt = JsonWebToken.DecodeToObject(token, "SOME_SECRET_KEY", verify: false);

            // Assert
            Assert.Equal(1L, jwt["key1"]);
            Assert.Equal("the-value", jwt["key2"]);
        }

        [Fact]
        public void InvalidKey_WithoutVerify_ReturnsPayload()
        {
            // Arrange
            var token = "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJrZXkxIjoxLCJrZXkyIjoidGhlLXZhbHVlIn0.z4nWl_itwSsz1SbxEZkxCmm9MMkIKanFvgGz_gsWIJo";

            // Act
            var jwt = JsonWebToken.DecodeToObject(token, "blah", verify: false);

            // Assert
            Assert.Equal(1L, jwt["key1"]);
            Assert.Equal("the-value", jwt["key2"]);
        }

        [Fact]
        public void DecodeHS256_Verifies_Correctly()
        {
            // Arrange
            var token = "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJrZXkxIjoxLCJrZXkyIjoidGhlLXZhbHVlIn0.z4nWl_itwSsz1SbxEZkxCmm9MMkIKanFvgGz_gsWIJo";

            // Act
            var jwt = JsonWebToken.DecodeToObject(token, "SOME_SECRET_KEY");

            // Assert
            Assert.Equal(1L, jwt["key1"]);
            Assert.Equal("the-value", jwt["key2"]);
        }

        [Fact]
        public void EncodeHs384Token_Returns_ExpectedToken()
        {
            // Arrange
            var payload = new Dictionary<string, object>()
            {
                { "key1", 1 },
                { "key2", "the-value" }
            };
            var secretKey = "SOME_SECRET_KEY";

            // Act
            var token = JsonWebToken.Encode(payload, secretKey, JwtHashAlgorithm.HS384);

            // Assert
            Assert.Equal("eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzM4NCJ9.eyJrZXkxIjoxLCJrZXkyIjoidGhlLXZhbHVlIn0.UKMB2eLfTwe_AupgNxAgX8hvGUYxivKjvonUCOhhY_EMpyMG8VVimu9E1GepOnvY", token);
        }

        [Fact]
        public void DecodeHS384_Verifies_Correctly()
        {
            // Arrange
            var token = "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzM4NCJ9.eyJrZXkxIjoxLCJrZXkyIjoidGhlLXZhbHVlIn0.UKMB2eLfTwe_AupgNxAgX8hvGUYxivKjvonUCOhhY_EMpyMG8VVimu9E1GepOnvY";

            // Act
            var jwt = JsonWebToken.DecodeToObject(token, "SOME_SECRET_KEY");

            // Assert
            Assert.Equal(1L, jwt["key1"]);
            Assert.Equal("the-value", jwt["key2"]);
        }

        [Fact]
        public void EncodeHs512Token_Returns_ExpectedToken()
        {
            // Arrange
            var payload = new Dictionary<string, object>()
            {
                { "key1", 1 },
                { "key2", "the-value" }
            };
            var secretKey = "SOME_SECRET_KEY";

            // Act
            var token = JsonWebToken.Encode(payload, secretKey, JwtHashAlgorithm.HS512);

            // Assert
            Assert.Equal("eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzUxMiJ9.eyJrZXkxIjoxLCJrZXkyIjoidGhlLXZhbHVlIn0.m6zcghjkZT6qZPFh5V6_oe-OKVmJtZ2orLYgFxhs1RxBMekftqVE0bE89LvU-q_eBBDfr7B3oA9SU_ZapQfPvQ", token);
        }

        [Fact]
        public void DecodeHS512_Verifies_Correctly()
        {
            // Arrange
            var token = "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzUxMiJ9.eyJrZXkxIjoxLCJrZXkyIjoidGhlLXZhbHVlIn0.m6zcghjkZT6qZPFh5V6_oe-OKVmJtZ2orLYgFxhs1RxBMekftqVE0bE89LvU-q_eBBDfr7B3oA9SU_ZapQfPvQ";

            // Act
            var jwt = JsonWebToken.DecodeToObject(token, "SOME_SECRET_KEY");

            // Assert
            Assert.Equal(1L, jwt["key1"]);
            Assert.Equal("the-value", jwt["key2"]);
        }

        [Fact]
        public void TokenWithExpiration_EncodesAndDecodes()
        {
            // Arrange
            var payload = new Dictionary<string, object>()
            {
                { "exp", Math.Round((DateTime.UtcNow.AddHours(1) - UnixEpoch).TotalSeconds) }
            };
            var secretKey = "SOME_SECRET_KEY";

            // Act
            var token = JsonWebToken.Encode(payload, secretKey, JwtHashAlgorithm.HS256);
            var decoded = JsonWebToken.DecodeToObject(token, secretKey);
            Assert.True(decoded.ContainsKey("exp"));
        }

        [Fact]
        public void ExpiredNowToken_ThrowsException()
        {
            // Arrange
            var payload = new Dictionary<string, object>()
            {
                // A timestamp of now is considered as expired
                { "exp", Math.Round((DateTime.UtcNow - UnixEpoch).TotalSeconds) }
            };
            var secretKey = "SOME_SECRET_KEY";

            // Act
            var token = JsonWebToken.Encode(payload, secretKey, JwtHashAlgorithm.HS256);
            var ex = Assert.Throws<SignatureVerificationException>(() => JsonWebToken.DecodeToObject(token, secretKey));
            Assert.Equal("Token has expired.", ex.Message);
        }

        [Fact]
        public void ExpiredToken_ThrowsException()
        {
            // Arrange
            var payload = new Dictionary<string, object>()
            {
                { "exp", Math.Round((DateTime.UtcNow.AddSeconds(-1) - UnixEpoch).TotalSeconds) }
            };
            var secretKey = "SOME_SECRET_KEY";

            // Act
            var token = JsonWebToken.Encode(payload, secretKey, JwtHashAlgorithm.HS256);
            var ex = Assert.Throws<SignatureVerificationException>(() => JsonWebToken.DecodeToObject(token, secretKey));
            Assert.Equal("Token has expired.", ex.Message);
        }
    }
}
