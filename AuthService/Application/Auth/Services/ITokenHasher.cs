namespace AuthService.Application.Auth.Services;

public interface ITokenHasher
{
    string Hash(string token);
}