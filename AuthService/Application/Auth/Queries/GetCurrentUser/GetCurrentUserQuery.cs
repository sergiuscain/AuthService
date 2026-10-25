using AuthService.Application.Auth.Common;
using MediatR;

namespace AuthService.Application.Auth.Queries.GetCurrentUser;

public record GetCurrentUserQuery(Guid UserId) : IRequest<UserDto?>;