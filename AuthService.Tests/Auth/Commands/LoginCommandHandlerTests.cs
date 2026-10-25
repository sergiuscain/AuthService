using AuthService.Application.Auth.Commands.Login;
using AuthService.Domain.Entities;
using AuthService.Domain.Enums;
using Microsoft.EntityFrameworkCore;

namespace AuthService.Tests.Auth.Commands;

public class LoginCommandHandlerTests
{
    private static async Task<User> SeedUserAsync(
        AuthService.Infrastructure.Persistence.AppDbContext db, string email, string password)
    {
        var hasher = new TestPasswordHasher();
        var user = new User
        {
            Id = Guid.NewGuid(),
            Email = email,
            Role = UserRole.User,
            CreatedAt = DateTime.UtcNow,
            UpdatedAt = DateTime.UtcNow
        };
        user.PasswordHash = hasher.Hash(user, password);
        db.Users.Add(user);
        await db.SaveChangesAsync();
        return user;
    }

    [Fact]
    public async Task Login_WithCorrectCredentials_ReturnsTokensAndSavesRefresh()
    {
        using var db = TestDb.Create();
        var user = await SeedUserAsync(db, "a@b.c", "secret123");

        var handler = new LoginCommandHandler(
    db, new TestPasswordHasher(), new TestJwtTokenGenerator(), new TestTokenHasher());

        var result = await handler.Handle(
            new LoginCommand("A@B.C", "secret123"), CancellationToken.None);

        Assert.StartsWith("access::", result.Tokens.AccessToken);
        Assert.False(string.IsNullOrWhiteSpace(result.RefreshToken));

        var stored = await db.RefreshTokens.SingleAsync();
        Assert.Equal(user.Id, stored.UserId);
        Assert.NotNull(stored.TokenHash);
        Assert.Null(stored.RevokedAt);
    }

    [Fact]
    public async Task Login_WithWrongPassword_Throws()
    {
        using var db = TestDb.Create();
        await SeedUserAsync(db, "a@b.c", "secret123");

        var handler = new LoginCommandHandler(
    db, new TestPasswordHasher(), new TestJwtTokenGenerator(), new TestTokenHasher());

        var ex = await Assert.ThrowsAsync<ArgumentException>(() =>
            handler.Handle(new LoginCommand("a@b.c", "wrong"), CancellationToken.None));

        Assert.Equal("Invalid email or password.", ex.Message);
    }

    [Fact]
    public async Task Login_WithUnknownEmail_ThrowsSameMessage()
    {
        using var db = TestDb.Create();
        var handler = new LoginCommandHandler(
    db, new TestPasswordHasher(), new TestJwtTokenGenerator(), new TestTokenHasher());

        var ex = await Assert.ThrowsAsync<ArgumentException>(() =>
            handler.Handle(new LoginCommand("nobody@local", "secret123"), CancellationToken.None));

        Assert.Equal("Invalid email or password.", ex.Message);
    }
}