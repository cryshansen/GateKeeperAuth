using System.Security.Claims;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;

var builder = WebApplication.CreateBuilder(args);

// 1. Configure the ASP.NET Core Secure Cookie Authentication Engine
builder.Services.AddAuthentication(CookieAuthenticationDefaults.AuthenticationScheme)
    .AddCookie(options =>
    {
        options.Cookie.Name = "GatekeeperSession";
        options.Cookie.HttpOnly = true; 
        options.Cookie.SameSite = SameSiteMode.Strict; 
        options.Cookie.SecurePolicy = CookieSecurePolicy.SameAsRequest; 
        options.ExpireTimeSpan = TimeSpan.FromMinutes(20);
        
        options.Events.OnRedirectToLogin = context =>
        {
            context.Response.StatusCode = StatusCodes.Status401Unauthorized;
            return Task.CompletedTask;
        };
    });

builder.Services.AddAuthorization();

var app = builder.Build();

// 2. Activate the Auth Engine Middlewares
app.UseAuthentication(); 
app.UseAuthorization();  

// ==========================================
// ENDPOINTS
// ==========================================

// Endpoint 1: Mock Authentication Gate
app.MapPost("/api/auth/login", async (LoginRequest request, HttpContext httpContext) =>
{
    if (request.Email == "crystal@dev.ca" && request.Password == "Password123")
    {
        var claims = new List<Claim>
        {
            new Claim(ClaimTypes.NameIdentifier, "USER-773"),
            new Claim(ClaimTypes.Email, request.Email),
            new Claim(ClaimTypes.Role, "Practitioner") 
        };

        var claimsIdentity = new ClaimsIdentity(claims, CookieAuthenticationDefaults.AuthenticationScheme);
        var userPrincipal = new ClaimsPrincipal(claimsIdentity);

        await httpContext.SignInAsync(CookieAuthenticationDefaults.AuthenticationScheme, userPrincipal);

        return Results.Ok(new { message = "Authentication successful. Secure cookie dropped." });
    }

    return Results.Unauthorized();
});

// Endpoint 2: A Guarded Route
app.MapGet("/api/secure/dashboard", (HttpContext httpContext) =>
{
    var userEmail = httpContext.User.FindFirst(ClaimTypes.Email)?.Value;
    var userRole = httpContext.User.FindFirst(ClaimTypes.Role)?.Value;

    return Results.Ok(new {
        message = "Welcome to the hidden zone!",
        identity = userEmail,
        accessLevel = userRole
    });
})
.RequireAuthorization();

// Endpoint 3: Logout
app.MapPost("/api/auth/logout", async (HttpContext httpContext) =>
{
    await httpContext.SignOutAsync(CookieAuthenticationDefaults.AuthenticationScheme);
    return Results.Ok(new { message = "Logged out successfully." });
});

app.Run();

// ====================================================================
// 3. TYPE/RECORD DECLARATIONS MUST GO AT THE ABSOLUTE BOTTOM
// ====================================================================
public record LoginRequest(string Email, string Password);