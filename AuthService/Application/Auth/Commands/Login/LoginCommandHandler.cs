using AuthService.Application.Auth.Common;
using AuthService.Application.Auth.Services;
using AuthService.Application.Common.Interfaces;
using AuthService.Domain.Entities;
using MediatR;
using Microsoft.EntityFrameworkCore;

namespace AuthService.Application.Auth.Commands.Login;

public sealed class LoginCommandHandler : IRequestHandler<LoginCommand, LoginResult>
{
    private readonly IAppDbContext _db;
    private readonly IPasswordHasher _passwordHasher;
    private readonly IJwtTokenGenerator _jwt;
    private readonly ITokenHasher _tokenHasher;

    public LoginCommandHandler(
        IAppDbContext db,
        IPasswordHasher passwordHasher,
        IJwtTokenGenerator jwt,
        ITokenHasher tokenHasher)
    {
        _db = db;
        _passwordHasher = passwordHasher;
        _jwt = jwt;
        _tokenHasher = tokenHasher;
    }

    public async Task<LoginResult> Handle(LoginCommand request, CancellationToken ct)
    {
        var email = (request.Email ?? string.Empty).Trim().ToLowerInvariant();

        var user = await _db.Users.FirstOrDefaultAsync(u => u.Email == email, ct);

        // Одинаковое сообщение для «нет пользователя» и «неверный пароль» —
        // чтобы не подсказывать, существует ли email.
        if (user is null || !_passwordHasher.Verify(user, user.PasswordHash, request.Password ?? string.Empty))
            throw new ArgumentException("Invalid email or password.");

        var accessToken = _jwt.GenerateAccessToken(user);
        var refreshToken = _jwt.GenerateRefreshToken();
        var refreshExpiresAt = _jwt.GetRefreshTokenExpiry();

        var refreshEntity = new RefreshToken
        {
            Id = Guid.NewGuid(),
            UserId = user.Id,
            TokenHash = _tokenHasher.Hash(refreshToken),
            ExpiresAt = refreshExpiresAt,
            CreatedAt = DateTime.UtcNow
        };
        _db.RefreshTokens.Add(refreshEntity);
        await _db.SaveChangesAsync(ct);

        var tokens = new AuthTokensDto(
            AccessToken: accessToken,
            AccessTokenExpiresAt: DateTime.UtcNow.AddMinutes(15),
            User: new UserDto(user.Id, user.Email, user.Role, user.CreatedAt));

        return new LoginResult(tokens, refreshToken, refreshExpiresAt);
    }
}