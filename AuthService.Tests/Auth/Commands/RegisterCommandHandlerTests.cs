using AuthService.Application.Auth.Commands.Register;
using AuthService.Domain.Enums;
using Microsoft.EntityFrameworkCore;

namespace AuthService.Tests.Auth.Commands;

public class RegisterCommandHandlerTests
{
    [Fact]
    public async Task Register_WithNewEmail_CreatesUser()
    {
        using var db = TestDb.Create();
        var handler = new RegisterCommandHandler(db, new TestPasswordHasher());

        var result = await handler.Handle(
            new RegisterCommand("Test@Local", "secret123"), CancellationToken.None);

        Assert.NotEqual(Guid.Empty, result.Id);
        Assert.Equal("test@local", result.Email);
        Assert.Equal(UserRole.User, result.Role);

        var saved = await db.Users.SingleAsync();
        Assert.Equal("test@local", saved.Email);
        Assert.Equal("hashed::secret123", saved.PasswordHash);
    }

    [Fact]
    public async Task Register_WithExistingEmail_Throws()
    {
        using var db = TestDb.Create();
        var handler = new RegisterCommandHandler(db, new TestPasswordHasher());

        await handler.Handle(new RegisterCommand("a@b.c", "secret123"), CancellationToken.None);

        var ex = await Assert.ThrowsAsync<ArgumentException>(() =>
            handler.Handle(new RegisterCommand("A@B.C", "another123"), CancellationToken.None));

        Assert.Contains("already exists", ex.Message);
    }

    [Fact]
    public async Task Register_WithShortPassword_Throws()
    {
        using var db = TestDb.Create();
        var handler = new RegisterCommandHandler(db, new TestPasswordHasher());

        var ex = await Assert.ThrowsAsync<ArgumentException>(() =>
            handler.Handle(new RegisterCommand("a@b.c", "123"), CancellationToken.None));

        Assert.Contains("at least 6", ex.Message);
    }
}