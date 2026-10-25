using AuthService.Application.Auth.Commands.Login;
using MediatR;

namespace AuthService.Application.Auth.Commands.Refresh;

public record RefreshCommand(string RefreshToken) : IRequest<LoginResult>;