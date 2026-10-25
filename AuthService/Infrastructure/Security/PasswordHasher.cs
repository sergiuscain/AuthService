using AuthService.Application.Auth.Services;
using AuthService.Domain.Entities;
using Microsoft.AspNetCore.Identity;

namespace AuthService.Infrastructure.Security;

public sealed class PasswordHasher : IPasswordHasher
{
    private readonly PasswordHasher<User> _inner = new();

    public string Hash(User user, string password)
        => _inner.HashPassword(user, password);

    public bool Verify(User user, string passwordHash, string providedPassword)
    {
        var result = _inner.VerifyHashedPassword(user, passwordHash, providedPassword);
        return result != PasswordVerificationResult.Failed;
    }
}