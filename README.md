# Jwt.NET
JSON Web Tokens implementation for .NET (including CoreCLR).

## Installation
 Jwt.NET is avaiable on [NuGet](https://www.nuget.org/packages/Jwt.NET).

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
