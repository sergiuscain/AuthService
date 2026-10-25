using AuthService.Application.Auth.Commands.Login;
using AuthService.Application.Auth.Common;
using AuthService.Application.Auth.Services;
using AuthService.Application.Common.Interfaces;
using AuthService.Domain.Entities;
using MediatR;
using Microsoft.EntityFrameworkCore;

namespace AuthService.Application.Auth.Commands.Refresh;

public sealed class RefreshCommandHandler : IRequestHandler<RefreshCommand, LoginResult>
{
    private readonly IAppDbContext _db;
    private readonly IJwtTokenGenerator _jwt;
    private readonly ITokenHasher _tokenHasher;

    public RefreshCommandHandler(
        IAppDbContext db,
        IJwtTokenGenerator jwt,
        ITokenHasher tokenHasher)
    {
        _db = db;
        _jwt = jwt;
        _tokenHasher = tokenHasher;
    }

    public async Task<LoginResult> Handle(RefreshCommand request, CancellationToken ct)
    {
        if (string.IsNullOrWhiteSpace(request.RefreshToken))
            throw new ArgumentException("Refresh token is required.");

        var hash = _tokenHasher.Hash(request.RefreshToken);

        var existing = await _db.RefreshTokens
            .FirstOrDefaultAsync(t => t.TokenHash == hash, ct);

        if (existing is null || !existing.IsActive)
            throw new ArgumentException("Invalid or expired refresh token.");

        var user = await _db.Users.FirstOrDefaultAsync(u => u.Id == existing.UserId, ct);
        if (user is null)
            throw new ArgumentException("Invalid or expired refresh token.");

        // Ротация: старый отзываем, новый создаём.
        existing.RevokedAt = DateTime.UtcNow;

        var newRefreshToken = _jwt.GenerateRefreshToken();
        var newRefreshExpiresAt = _jwt.GetRefreshTokenExpiry();

        var newRefreshEntity = new RefreshToken
        {
            Id = Guid.NewGuid(),
            UserId = user.Id,
            TokenHash = _tokenHasher.Hash(newRefreshToken),
            ExpiresAt = newRefreshExpiresAt,
            CreatedAt = DateTime.UtcNow
        };
        _db.RefreshTokens.Add(newRefreshEntity);

        await _db.SaveChangesAsync(ct);

        var accessToken = _jwt.GenerateAccessToken(user);

        var tokens = new AuthTokensDto(
            AccessToken: accessToken,
            AccessTokenExpiresAt: DateTime.UtcNow.AddMinutes(15),
            User: new UserDto(user.Id, user.Email, user.Role, user.CreatedAt));

        return new LoginResult(tokens, newRefreshToken, newRefreshExpiresAt);
    }
}