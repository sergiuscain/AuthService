namespace AuthService.Application.Auth.Common;

public record AuthTokensDto(
    string AccessToken,
    DateTime AccessTokenExpiresAt,
    UserDto User);