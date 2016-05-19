# Jwt.NET
JSON Web Tokens implementation for .NET Core.

<hr>

| Windows | Linux | OS X |
| --- | --- | --- |
| [![Build status](https://ci.appveyor.com/api/projects/status/kr49ieh4vp3c9cxt?svg=true)](https://ci.appveyor.com/project/henkmollema/jwt-net) | [![Build Status](https://travis-ci.org/henkmollema/Jwt.NET.svg)](https://travis-ci.org/henkmollema/Jwt.NET) | [![Build Status](https://travis-ci.org/henkmollema/Jwt.NET.svg)](https://travis-ci.org/henkmollema/Jwt.NET) |

--

## Installation
 Jwt.NET is avaiable on [NuGet](https://www.nuget.org/packages/JsonWebTokens).

## Usage
### Creating tokens

```csharp
var payload = new Dictionary<string, object>()
{
    { "key1", 1 },
    { "key2", "the-value" }
};
var secret = "SOME_SECRET_KEY";
var token = Jwt.JsonWebToken.Encode(payload, secretKey, Jwt.JwtHashAlgorithm.HS256);
```

Output: 
```
eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJrZXkxIjoxLCJrZXkyIjoidGhlLXZhbHVlIn0.z4nWl_itwSsz1SbxEZkxCmm9MMkIKanFvgGz_gsWIJo
```

### Decoding and verifying tokens
```csharp
var token = "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJrZXkxIjoxLCJrZXkyIjoidGhlLXZhbHVlIn0.z4nWl_itwSsz1SbxEZkxCmm9MMkIKanFvgGz_gsWIJo"
var secret = "SOME_SECRET_KEY";

try
{
    var data = JsonWebToken.Decode(token, secret);
}
catch (SignatureVerificationException)
{
    // Given token is either expired or hashed with an unsupported algorithm.
}
```

Output:
```
{"key1":1,"key2":"the-value"}
```

#### Typed objects
You can use the `DecodeToObject` method to deserialize the decoded payload:
```csharp
var token = "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJrZXkxIjoxLCJrZXkyIjoidGhlLXZhbHVlIn0.z4nWl_itwSsz1SbxEZkxCmm9MMkIKanFvgGz_gsWIJo"
var secret = "SOME_SECRET_KEY";

var decoded = JsonWebToken.DecodeToObject<Dictionary<string, object>>(token, secret);
```

### Advanced
If you need advanced settings when encoding data, you can use the `JwtBuilder` class to build a `JwtData` object. This allows you to pass in an already serialized payload or append extra headers for example.

```csharp
var serializedPayload = JsonConvert.SerializeObject(payload);
var secret = "SOME_SECRET_KEY";

var jwtData = new JwtBuilder()
    .WithPayload(serializedPayload)
    .IsSerialized()
    .WithKey(secret)
    .WithAlgorithm(JwtHashAlgorithm.HS512)
    .WithHeader("exp", 60 * 60)
    .Build();

var token = JsonWebToken.Encode(jwtData);
```
