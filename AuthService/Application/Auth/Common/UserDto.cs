using AuthService.Domain.Enums;

namespace AuthService.Application.Auth.Common;

public record UserDto(
    Guid Id,
    string Email,
    UserRole Role,
    DateTime CreatedAt);