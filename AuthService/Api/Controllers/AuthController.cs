using Microsoft.AspNetCore.Mvc;

namespace AuthService.Api.Controllers;

/// <summary>Аутентификация и выдача токенов.</summary>
[ApiController]
[Route("auth")]
public class AuthController : ControllerBase
{
    /// <summary>Регистрация нового пользователя.</summary>
    /// <response code="501">Пока не реализовано.</response>
    [HttpPost("register")]
    public IActionResult Register()
        => StatusCode(StatusCodes.Status501NotImplemented, new { message = "Not implemented yet." });

    /// <summary>Логин. Устанавливает cookie и возвращает access token.</summary>
    /// <response code="501">Пока не реализовано.</response>
    [HttpPost("login")]
    public IActionResult Login()
        => StatusCode(StatusCodes.Status501NotImplemented, new { message = "Not implemented yet." });

    /// <summary>Обновить access token по refresh token.</summary>
    /// <response code="501">Пока не реализовано.</response>
    [HttpPost("refresh")]
    public IActionResult Refresh()
        => StatusCode(StatusCodes.Status501NotImplemented, new { message = "Not implemented yet." });

    /// <summary>Выход. Отзывает refresh token и чистит cookie.</summary>
    /// <response code="501">Пока не реализовано.</response>
    [HttpPost("logout")]
    public IActionResult Logout()
        => StatusCode(StatusCodes.Status501NotImplemented, new { message = "Not implemented yet." });
}