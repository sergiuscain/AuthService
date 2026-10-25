using MediatR;

namespace AuthService.Application.Auth.Commands.Logout;

public record LogoutCommand(string? RefreshToken) : IRequest;