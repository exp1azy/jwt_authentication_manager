# JWTAuthenticationManager

This library provides a reusable implementation of JWT-based authentication for ASP.NET Core applications. The goal is to avoid repeating boilerplate code across projects and simplify the setup of secure, token-based authentication. The library is intended for internal use or integration into microservices where consistent authentication logic is required.

## Usage
Add JWT authentication in `Program.cs`
```csharp
builder.Services.AddJwtAuthentication(
    new JwtBearerOptions
    {
        RequireHttpsMetadata = false,
        TokenValidationParameters = new TokenValidationParameters
        {
            ValidateIssuer = false,
            ValidateAudience = false,
            ValidateLifetime = true,
            IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(jwtSecret)),
            ValidateIssuerSigningKey = true,
            ClockSkew = TimeSpan.Zero,
            NameClaimType = nameClaimType
        },
        Events = new JwtBearerEvents
        {
            OnTokenValidated = ctx =>
            {
                var clsOnly = ctx.Principal.Claims.Any(c => c.Type == "clsOnly" && c.Value == "true");
                var clsRequest = ClsRequests.Any(r => ctx.Request.Path.Value?.StartsWith(r) ?? false);

                if (clsOnly && !clsRequest)
                    ctx.Fail(Error.ClsOnlyError);

                return Task.CompletedTask;
            }
        }
    }, 
    new JwtSettings
    {
        SecretKey = jwtSecret,
        ExpirationInMinutes = 240
    }
);
```
**! you don't have to write `AddAuthorization()`, because the `AddJwtAuthentication()` method already does that !**
---
Then you can use the `IJwtAuthenticationManager` interface in your services and controllers from DI container:
```csharp
[ApiController]
[Route("api")]   
public class AuthenticationController : ControllerBase
{
    private readonly IJwtAuthenticationManager _authManager;

    public AuthenticationController(IJwtAuthenticationManager authManager)
    {
        _authManager = authManager;
    }
}
```
There is some examples how you can generate tokens and get remaining token lifespan in seconds:
```csharp
[HttpPost("auth")]
[AllowAnonymous]       
public async Task<IActionResult> AuthAsync([FromBody] AuthenticationDTOModel auth, CancellationToken cancellationToken)
{
    if (!ModelState.IsValid) 
        return BadRequest($"Невалидные данные для {nameof(auth)}.");

    try
    {
        var user = await _userServiсe.CheckUserAsync(auth.Login, auth.ClientTitle, auth.Password, cancellationToken);
        if (user == null) return Unauthorized();

        var token = _authManager.GenerateToken(new List<Claim>
        {
            new("userName", user.UserName),
            new("clientTitle", Convert.ToBase64String(Encoding.UTF8.GetBytes(string.IsNullOrEmpty(user.ClientTitle) ? "" : user.ClientTitle))),
            new("clientId", (user.ClientId ?? 0).ToString()),
            new("userId", user.Id.ToString()),
            new("isSuper", user.IsAdmin.ToString()),
            new("isAdmin", user.IsAdmin.ToString()),
            new("login", Convert.ToBase64String(Encoding.UTF8.GetBytes(user.UserName))),
        });

        return Ok(new { token });
    }
    catch (Exception ex)
    {
        return StatusCode(500, ex.Message);
    }
}

[Authorize]
[HttpGet("remaining-lifetime")]
public IActionResult GetRemainingTokenLifetime()
{
    _ = HttpContext.Request.Headers.TryGetValue("Authorization", out var token);

    try
    {
        var totalSeconds = _authManager.GetRemainingLifeTime(token.ToString());
        return Ok(totalSeconds);
    }
    catch (Exception)
    {
        return NotFound(Error.NoJWTInHeader);
    }
}
```
