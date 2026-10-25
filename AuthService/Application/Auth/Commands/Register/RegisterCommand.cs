using AuthService.Application.Auth.Common;
using MediatR;

namespace AuthService.Application.Auth.Commands.Register;

public record RegisterCommand(string Email, string Password) : IRequest<UserDto>;