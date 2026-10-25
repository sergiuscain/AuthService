using AuthService.Application.Auth.Services;
using AuthService.Domain.Entities;

namespace AuthService.Tests;

internal sealed class TestPasswordHasher : IPasswordHasher
{
    public string Hash(User user, string password) => $"hashed::{password}";

    public bool Verify(User user, string passwordHash, string providedPassword)
        => passwordHash == $"hashed::{providedPassword}";
}