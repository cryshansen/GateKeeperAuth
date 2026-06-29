using System.Security.Claims;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;

var builder = WebApplication.CreateBuilder(args);

// define a CORS policy to allow requests from the front-end
builder.Services.AddCors(options =>
{
    options.AddPolicy("ReactAppPolicy", policy =>
    {
        policy.WithOrigins("http://localhost:3000", "https://proud-moss-0cfd07110.azurestaticapps.net") // Replace with your front-end URL
              .AllowAnyHeader()
              .AllowAnyMethod()
              .AllowCredentials(); // CRITICAL: Allows cookies to pass through CORS
    });
});


// 1. Configure the ASP.NET Core Secure Cookie Authentication Engine
builder.Services.AddAuthentication(CookieAuthenticationDefaults.AuthenticationScheme)
    .AddCookie(options =>
    {
        options.Cookie.Name = "GatekeeperSession";
        options.Cookie.HttpOnly = true; 
        options.Cookie.SameSite = SameSiteMode.None; 
        options.Cookie.SecurePolicy = CookieSecurePolicy.Always; 
        options.ExpireTimeSpan = TimeSpan.FromMinutes(20);
        
        options.Events.OnRedirectToLogin = context =>
        {
            context.Response.StatusCode = StatusCodes.Status401Unauthorized;
            return Task.CompletedTask;
        };
        // Custom handler for when a user IS logged in, but doesn't have the right role
        options.Events.OnRedirectToAccessDenied = context =>
        {
            context.Response.StatusCode = StatusCodes.Status403Forbidden;
            return Task.CompletedTask;
        };
    });

builder.Services.AddAuthorization();

var app = builder.Build();

// 2. Activate the CORS and Auth Engine Middlewares (order matters: CORS before auth)
app.UseCors("ReactAppPolicy");
app.UseAuthentication();
app.UseAuthorization();

// ==========================================
// ENDPOINTS
// ==========================================

// Modified Login Gate: Allows choosing your role via payload for testing
app.MapPost("/api/auth/login", async (LoginRequest request, HttpContext httpContext) =>
{
    // Mock user database logic
    string assignedRole = request.Email == "admin@dev.ca" ? "Admin" : "Practitioner";

    if (request.Password == "Password123")
    {
        var claims = new List<Claim>
        {
            new Claim(ClaimTypes.NameIdentifier, "USER-773"),
            new Claim(ClaimTypes.Email, request.Email),
            new Claim(ClaimTypes.Role, assignedRole) // Setting the dynamic role here!
        };

        var claimsIdentity = new ClaimsIdentity(claims, CookieAuthenticationDefaults.AuthenticationScheme);
        var userPrincipal = new ClaimsPrincipal(claimsIdentity);

        await httpContext.SignInAsync(CookieAuthenticationDefaults.AuthenticationScheme, userPrincipal);

        return Results.Ok(new { message = $"Logged in successfully as an {assignedRole}." });
    }

    return Results.Unauthorized();
});
// Endpoint 2: Standard Secure Route (Accessible by ANY authenticated user)
app.MapGet("/api/secure/dashboard", (HttpContext httpContext) =>
{
    var userEmail = httpContext.User.FindFirst(ClaimTypes.Email)?.Value;
    var userRole = httpContext.User.FindFirst(ClaimTypes.Role)?.Value;

    return Results.Ok(new {
        message = "Welcome to the base secure dashboard!",
        identity = userEmail,
        role = userRole
    });
})
.RequireAuthorization();

// Endpoint 3: Highly Restricted Route (ONLY Admins allowed)
app.MapDelete("/api/secure/delete-record/{id}", (int id, HttpContext httpContext) =>
{
    return Results.Ok(new {
        message = $"CRITICAL: Record {id} has been permanently purged from the system by an Administrator."
    });
})
.RequireAuthorization(policy => policy.RequireRole("Admin")); // RBAC Guard Clause

// Logout
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