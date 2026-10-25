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