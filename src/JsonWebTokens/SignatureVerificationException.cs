using System;

namespace Jwt
{
    public class SignatureVerificationException : Exception
    {
        public SignatureVerificationException(string message) : base(message)
        {
        }
    }
}
