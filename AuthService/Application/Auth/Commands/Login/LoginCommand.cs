using AuthService.Application.Auth.Common;
using MediatR;

namespace AuthService.Application.Auth.Commands.Login;

public record LoginCommand(string Email, string Password) : IRequest<LoginResult>;

public record LoginResult(AuthTokensDto Tokens, string RefreshToken, DateTime RefreshTokenExpiresAt);