using AuthService.Domain.Entities;

namespace AuthService.Application.Auth.Services;

public interface IPasswordHasher
{
    string Hash(User user, string password);
    bool Verify(User user, string passwordHash, string providedPassword);
}