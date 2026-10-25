using AuthService.Application.Auth.Commands.Login;
using AuthService.Application.Auth.Commands.Logout;
using AuthService.Application.Auth.Commands.Refresh;
using AuthService.Application.Auth.Commands.Register;
using AuthService.Application.Auth.Common;
using MediatR;
using Microsoft.AspNetCore.Mvc;

namespace AuthService.Api.Controllers;

/// <summary>Аутентификация и выдача токенов.</summary>
[ApiController]
[Route("auth")]
public class AuthController : ControllerBase
{
    private readonly IMediator _mediator;

    public AuthController(IMediator mediator) => _mediator = mediator;

    /// <summary>Регистрация нового пользователя.</summary>
    /// <response code="201">Пользователь создан.</response>
    /// <response code="400">Ошибка валидации или email уже занят.</response>
    [HttpPost("register")]
    public async Task<ActionResult<UserDto>> Register(
    [FromBody] RegisterCommand command, CancellationToken ct)
    {
        try
        {
            var user = await _mediator.Send(command, ct);
            return StatusCode(StatusCodes.Status201Created, user);
        }
        catch (ArgumentException ex)
        {
            return BadRequest(new { error = ex.Message });
        }
    }


    [HttpPost("login")]
    public async Task<ActionResult<AuthTokensDto>> Login(
    [FromBody] LoginCommand command, CancellationToken ct)
    {
        try
        {
            var result = await _mediator.Send(command, ct);

            var cookieOptions = new CookieOptions
            {
                HttpOnly = true,
                Secure = Request.IsHttps,
                SameSite = SameSiteMode.Lax,
                Path = "/"
            };

            Response.Cookies.Append(
                "access_token", result.Tokens.AccessToken,
                new CookieOptions
                {
                    HttpOnly = true,
                    Secure = Request.IsHttps,
                    SameSite = SameSiteMode.Lax,
                    Path = "/",
                    Expires = result.Tokens.AccessTokenExpiresAt
                });

            Response.Cookies.Append(
                "refresh_token", result.RefreshToken,
                new CookieOptions
                {
                    HttpOnly = true,
                    Secure = Request.IsHttps,
                    SameSite = SameSiteMode.Lax,
                    Path = "/",
                    Expires = result.RefreshTokenExpiresAt
                });

            return Ok(result.Tokens);
        }
        catch (ArgumentException ex)
        {
            return BadRequest(new { error = ex.Message });
        }
    }

    /// <summary>Обновить access token по refresh token.</summary>
    /// <response code="501">Пока не реализовано.</response>
    [HttpPost("refresh")]
    public async Task<ActionResult<AuthTokensDto>> Refresh(CancellationToken ct)
    {
        // Refresh-токен приходит из cookie. Если клиент не-браузерный (Bearer-сценарий) —
        // можно передать в теле. Пока поддерживаем только cookie.
        if (!Request.Cookies.TryGetValue("refresh_token", out var refreshToken)
            || string.IsNullOrWhiteSpace(refreshToken))
        {
            return Unauthorized(new { error = "Refresh token cookie is missing." });
        }

        try
        {
            var result = await _mediator.Send(new RefreshCommand(refreshToken), ct);

            var cookieBase = new CookieOptions
            {
                HttpOnly = true,
                Secure = Request.IsHttps,
                SameSite = SameSiteMode.Lax,
                Path = "/"
            };

            Response.Cookies.Append("access_token", result.Tokens.AccessToken,
                new CookieOptions
                {
                    HttpOnly = true,
                    Secure = Request.IsHttps,
                    SameSite = SameSiteMode.Lax,
                    Path = "/",
                    Expires = result.Tokens.AccessTokenExpiresAt
                });

            Response.Cookies.Append("refresh_token", result.RefreshToken,
                new CookieOptions
                {
                    HttpOnly = true,
                    Secure = Request.IsHttps,
                    SameSite = SameSiteMode.Lax,
                    Path = "/",
                    Expires = result.RefreshTokenExpiresAt
                });

            return Ok(result.Tokens);
        }
        catch (ArgumentException ex)
        {
            // При ошибке чистим cookie — не даём клиенту долбиться с протухшим токеном.
            Response.Cookies.Delete("access_token");
            Response.Cookies.Delete("refresh_token");
            return Unauthorized(new { error = ex.Message });
        }
    }

    /// <summary>Выход. Отзывает refresh token и чистит cookie.</summary>
    /// <response code="501">Пока не реализовано.</response>
    [HttpPost("logout")]
    public async Task<IActionResult> Logout(CancellationToken ct)
    {
        Request.Cookies.TryGetValue("refresh_token", out var refreshToken);

        await _mediator.Send(new LogoutCommand(refreshToken), ct);

        Response.Cookies.Delete("access_token");
        Response.Cookies.Delete("refresh_token");

        return NoContent();
    }
}