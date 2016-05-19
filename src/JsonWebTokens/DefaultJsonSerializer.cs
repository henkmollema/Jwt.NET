using Newtonsoft.Json;

namespace Jwt
{
    /// <summary>
    /// <see cref="IJsonSerializer"/> implementation using Json.NET.
    /// </summary>
    public class DefaultJsonSerializer : IJsonSerializer
    {
        /// <inheritdoc />
        public string Serialize(object value)
        {
            return JsonConvert.SerializeObject(value);
        }

        /// <inheritdoc />
        public T Deserialize<T>(string value)
        {
            return JsonConvert.DeserializeObject<T>(value);
        }
    }
}
