using AuthService.Application.Auth.Services;
using AuthService.Domain.Entities;

namespace AuthService.Tests;

internal sealed class TestJwtTokenGenerator : IJwtTokenGenerator
{
    public string GenerateAccessToken(User user) => $"access::{user.Id}";

    public string GenerateRefreshToken() => Guid.NewGuid().ToString();

    public DateTime GetRefreshTokenExpiry() => DateTime.UtcNow.AddDays(7);
}