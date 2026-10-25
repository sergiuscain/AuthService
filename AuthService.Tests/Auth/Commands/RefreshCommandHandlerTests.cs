using AuthService.Application.Auth.Commands.Login;
using AuthService.Application.Auth.Commands.Refresh;
using AuthService.Domain.Entities;
using AuthService.Domain.Enums;
using Microsoft.EntityFrameworkCore;

namespace AuthService.Tests.Auth.Commands;

public class RefreshCommandHandlerTests
{
    private static async Task<string> SeedLoginAsync(
        AuthService.Infrastructure.Persistence.AppDbContext db)
    {
        var hasher = new TestPasswordHasher();
        var jwt = new TestJwtTokenGenerator();

        var user = new User
        {
            Id = Guid.NewGuid(),
            Email = "a@b.c",
            Role = UserRole.User,
            CreatedAt = DateTime.UtcNow,
            UpdatedAt = DateTime.UtcNow
        };
        user.PasswordHash = hasher.Hash(user, "secret123");
        db.Users.Add(user);
        await db.SaveChangesAsync();

        var login = new LoginCommandHandler(db, hasher, jwt, new TestTokenHasher());
        var result = await login.Handle(
            new LoginCommand("a@b.c", "secret123"), CancellationToken.None);

        return result.RefreshToken;
    }

    [Fact]
    public async Task Refresh_WithValidToken_RotatesAndReturnsNewTokens()
    {
        using var db = TestDb.Create();
        var refresh = await SeedLoginAsync(db);

        var tokenHasher = new TestTokenHasher();
        var handler = new RefreshCommandHandler(db, new TestJwtTokenGenerator(), tokenHasher);

        var result = await handler.Handle(new RefreshCommand(refresh), CancellationToken.None);

        Assert.False(string.IsNullOrWhiteSpace(result.RefreshToken));
        Assert.NotEqual(refresh, result.RefreshToken);

        var all = await db.RefreshTokens.AsNoTracking().ToListAsync();
        Assert.Equal(2, all.Count);

        var old = all.Single(t => t.TokenHash == tokenHasher.Hash(refresh));
        Assert.NotNull(old.RevokedAt);

        var fresh = all.Single(t => t.TokenHash == tokenHasher.Hash(result.RefreshToken));
        Assert.Null(fresh.RevokedAt);
    }

    [Fact]
    public async Task Refresh_WithUnknownToken_Throws()
    {
        using var db = TestDb.Create();
        var handler = new RefreshCommandHandler(db, new TestJwtTokenGenerator(), new TestTokenHasher());

        var ex = await Assert.ThrowsAsync<ArgumentException>(() =>
            handler.Handle(new RefreshCommand("nonsense"), CancellationToken.None));

        Assert.Equal("Invalid or expired refresh token.", ex.Message);
    }

    [Fact]
    public async Task Refresh_WithRevokedToken_Throws()
    {
        using var db = TestDb.Create();
        var refresh = await SeedLoginAsync(db);

        var tokenHasher = new TestTokenHasher();
        var handler = new RefreshCommandHandler(db, new TestJwtTokenGenerator(), tokenHasher);

        // Первый refresh — успешен: старый отозван, новый создан.
        await handler.Handle(new RefreshCommand(refresh), CancellationToken.None);

        // Повторный с тем же (уже отозванным) токеном — должен упасть.
        var ex = await Assert.ThrowsAsync<ArgumentException>(() =>
            handler.Handle(new RefreshCommand(refresh), CancellationToken.None));

        Assert.Equal("Invalid or expired refresh token.", ex.Message);
    }
}