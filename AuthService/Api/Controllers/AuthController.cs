using AuthService.Application.Auth.Commands.Login;
using AuthService.Application.Auth.Commands.Logout;
using AuthService.Application.Auth.Commands.Refresh;
using AuthService.Application.Auth.Commands.Register;
using AuthService.Application.Auth.Common;
using AuthService.Application.Auth.Queries.GetCurrentUser;
using MediatR;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;

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

    /// <summary>Логин. Устанавливает cookie access_token и refresh_token и возвращает access token в теле.</summary>
    /// <response code="200">Успешный логин. Access token в теле, refresh — только в cookie.</response>
    /// <response code="400">Неверный email или пароль.</response>
    [HttpPost("login")]
    public async Task<ActionResult<AuthTokensDto>> Login(
        [FromBody] LoginCommand command, CancellationToken ct)
    {
        try
        {
            var result = await _mediator.Send(command, ct);

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

    /// <summary>Обновить access token по refresh token из cookie. Старый refresh отзывается, выдаётся новый.</summary>
    /// <response code="200">Новые токены. Cookie перезаписаны, access token — в теле.</response>
    /// <response code="401">Refresh token отсутствует, истёк или отозван. Cookie очищены.</response>
    [HttpPost("refresh")]
    public async Task<ActionResult<AuthTokensDto>> Refresh(CancellationToken ct)
    {
        if (!Request.Cookies.TryGetValue("refresh_token", out var refreshToken)
            || string.IsNullOrWhiteSpace(refreshToken))
        {
            return Unauthorized(new { error = "Refresh token cookie is missing." });
        }

        try
        {
            var result = await _mediator.Send(new RefreshCommand(refreshToken), ct);

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
            Response.Cookies.Delete("access_token");
            Response.Cookies.Delete("refresh_token");
            return Unauthorized(new { error = ex.Message });
        }
    }

    /// <summary>Выход. Отзывает текущий refresh token и чистит cookie. Идемпотентен.</summary>
    /// <response code="204">Выход выполнен (или пользователь уже не был залогинен).</response>
    [HttpPost("logout")]
    public async Task<IActionResult> Logout(CancellationToken ct)
    {
        Request.Cookies.TryGetValue("refresh_token", out var refreshToken);

        await _mediator.Send(new LogoutCommand(refreshToken), ct);

        Response.Cookies.Delete("access_token");
        Response.Cookies.Delete("refresh_token");

        return NoContent();
    }

    /// <summary>Информация о текущем аутентифицированном пользователе.</summary>
    /// <response code="200">Пользователь найден.</response>
    /// <response code="401">Токен отсутствует или невалиден.</response>
    /// <response code="404">Пользователь из токена не найден в БД.</response>
    [Authorize]
    [HttpGet("me")]
    public async Task<ActionResult<UserDto>> Me(CancellationToken ct)
    {
        // JwtBearer по умолчанию мапит "sub" в ClaimTypes.NameIdentifier.
        // Берём оттуда, с fallback на "sub" — на случай другой настройки TokenValidationParameters.
        var sub = User.FindFirstValue(ClaimTypes.NameIdentifier)
                  ?? User.FindFirstValue(JwtRegisteredClaimNames.Sub);

        if (!Guid.TryParse(sub, out var userId))
            return Unauthorized(new { error = "Invalid user identifier in token." });

        var user = await _mediator.Send(new GetCurrentUserQuery(userId), ct);
        return user is null ? NotFound() : Ok(user);
    }
}