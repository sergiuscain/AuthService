using AuthService.Application.Auth.Services;

namespace AuthService.Tests;

internal sealed class TestTokenHasher : ITokenHasher
{
    public string Hash(string token) => $"hash::{token}";
}