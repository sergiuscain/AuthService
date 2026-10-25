using AuthService.Domain.Entities;

namespace AuthService.Application.Auth.Services;

public interface IJwtTokenGenerator
{
    string GenerateAccessToken(User user);
    string GenerateRefreshToken();
    DateTime GetRefreshTokenExpiry();
}