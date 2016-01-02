using Newtonsoft.Json;

namespace Jwt
{
    /// <summary>
    /// <see cref="IJsonSerializer"/> implementation using Json.NET.
    /// </summary>
    public class DefaultJsonSerializer : IJsonSerializer
    {
        public string Serialize(object value)
        {
            return JsonConvert.SerializeObject(value);
        }

        public T Deserialize<T>(string value)
        {
            return JsonConvert.DeserializeObject<T>(value);
        }
    }
}
