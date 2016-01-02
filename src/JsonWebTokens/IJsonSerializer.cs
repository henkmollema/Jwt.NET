namespace Jwt
{
    /// <summary>
    /// Specifies a contract for a JSON serializer implementation.
    /// </summary>
    public interface IJsonSerializer
    {
        /// <summary>
        /// Serializes an object to a JSON string.
        /// </summary>
        /// <param name="value">The value to serialize.</param>
        /// <returns>A JSON string representing of the object.</returns>
        string Serialize(object value);

        /// <summary>
        /// Deserializes a JSON string to a typed object of type <typeparamref name="T"/>.
        /// </summary>
        /// <typeparam name="T">The type of the object.</typeparam>
        /// <param name="value">A JSON string representing the object.</param>
        /// <returns>A typed object of type <typeparamref name="T"/>.</returns>
        T Deserialize<T>(string value);
    }
}
