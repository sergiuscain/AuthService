using AuthService.Application.Auth.Services;
using AuthService.Domain.Entities;
using AuthService.Domain.Enums;
using Microsoft.EntityFrameworkCore;

namespace AuthService.Infrastructure.Persistence;

public static class DataSeeder
{
    public static async Task SeedAdminAsync(
        AppDbContext db,
        IPasswordHasher passwordHasher,
        IConfiguration configuration,
        ILogger logger,
        CancellationToken ct = default)
    {
        var adminExists = await db.Users.AnyAsync(u => u.Role == UserRole.Admin, ct);
        if (adminExists)
            return;

        var email = configuration["Seed:AdminEmail"] ?? "admin@local";
        var password = configuration["Seed:AdminPassword"] ?? "Admin123!";

        var admin = new User
        {
            Id = Guid.NewGuid(),
            Email = email.Trim().ToLowerInvariant(),
            Role = UserRole.Admin,
            CreatedAt = DateTime.UtcNow,
            UpdatedAt = DateTime.UtcNow
        };
        admin.PasswordHash = passwordHasher.Hash(admin, password);

        db.Users.Add(admin);
        await db.SaveChangesAsync(ct);

        logger.LogWarning(
            "Seeded default admin user '{Email}'. Change the password via Seed:AdminPassword env in production.",
            email);
    }
}