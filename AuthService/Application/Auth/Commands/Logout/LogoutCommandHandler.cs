using AuthService.Application.Auth.Services;
using AuthService.Application.Common.Interfaces;
using MediatR;
using Microsoft.EntityFrameworkCore;

namespace AuthService.Application.Auth.Commands.Logout;

public sealed class LogoutCommandHandler : IRequestHandler<LogoutCommand>
{
    private readonly IAppDbContext _db;
    private readonly ITokenHasher _tokenHasher;

    public LogoutCommandHandler(IAppDbContext db, ITokenHasher tokenHasher)
    {
        _db = db;
        _tokenHasher = tokenHasher;
    }

    public async Task Handle(LogoutCommand request, CancellationToken ct)
    {
        if (string.IsNullOrWhiteSpace(request.RefreshToken))
            return;

        var hash = _tokenHasher.Hash(request.RefreshToken);

        var existing = await _db.RefreshTokens
            .FirstOrDefaultAsync(t => t.TokenHash == hash, ct);

        // Нет токена или уже отозван — logout идемпотентен, ничего не делаем.
        if (existing is null || existing.RevokedAt is not null)
            return;

        existing.RevokedAt = DateTime.UtcNow;
        await _db.SaveChangesAsync(ct);
    }
}