using System;
using System.Collections.Generic;
using Xunit;

namespace Jwt.Tests
{
    public class JsonWebTokenTests
    {
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
    }
}
