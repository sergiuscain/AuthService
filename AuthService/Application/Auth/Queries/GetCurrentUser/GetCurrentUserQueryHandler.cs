using AuthService.Application.Auth.Common;
using AuthService.Application.Common.Interfaces;
using MediatR;
using Microsoft.EntityFrameworkCore;

namespace AuthService.Application.Auth.Queries.GetCurrentUser;

public sealed class GetCurrentUserQueryHandler : IRequestHandler<GetCurrentUserQuery, UserDto?>
{
    private readonly IAppDbContext _db;

    public GetCurrentUserQueryHandler(IAppDbContext db) => _db = db;

    public async Task<UserDto?> Handle(GetCurrentUserQuery request, CancellationToken ct)
    {
        return await _db.Users
            .AsNoTracking()
            .Where(u => u.Id == request.UserId)
            .Select(u => new UserDto(u.Id, u.Email, u.Role, u.CreatedAt))
            .FirstOrDefaultAsync(ct);
    }
}