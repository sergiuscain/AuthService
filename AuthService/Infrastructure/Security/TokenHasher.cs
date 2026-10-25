using AuthService.Application.Auth.Services;
using System.Security.Cryptography;
using System.Text;

namespace AuthService.Infrastructure.Security;

public sealed class TokenHasher : ITokenHasher
{
    public string Hash(string token)
    {
        var bytes = Encoding.UTF8.GetBytes(token);
        var hash = SHA256.HashData(bytes);
        return Convert.ToHexString(hash);
    }
}