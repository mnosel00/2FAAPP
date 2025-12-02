using _2FA_Backend.Application.Interfaces;
using _2FA_Backend.Application.Services;
using _2FA_Backend.Domain.Interfaces;
using _2FA_Backend.Infastructure.Data;
using _2FA_Backend.Infastructure.Repositories;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;
using Scalar.AspNetCore;
using System.Text;

var builder = WebApplication.CreateBuilder(args);

// 1. Konfiguracja bazy danych
builder.Services.AddDbContext<ApplicationDbContext>(options =>
    options.UseSqlServer(builder.Configuration.GetConnectionString("DefaultConnection")));

// 2. Identity Config
builder.Services.AddIdentity<IdentityUser, IdentityRole>(options =>
{
    options.Tokens.AuthenticatorTokenProvider = TokenOptions.DefaultAuthenticatorProvider;
    options.User.RequireUniqueEmail = true; // Wymagaj unikalnych emaili
})
.AddEntityFrameworkStores<ApplicationDbContext>()
.AddDefaultTokenProviders();

// 3. Cookie Config (Identity)
builder.Services.ConfigureApplicationCookie(options =>
{
    options.Cookie.SameSite = SameSiteMode.None;
    options.Cookie.SecurePolicy = CookieSecurePolicy.Always;
    options.Cookie.HttpOnly = true;
    options.Events.OnRedirectToLogin = context =>
    {
        context.Response.StatusCode = StatusCodes.Status401Unauthorized;
        return Task.CompletedTask;
    };
});

builder.Services.ConfigureExternalCookie(options =>
{
    options.Cookie.SameSite = SameSiteMode.None;
    options.Cookie.SecurePolicy = CookieSecurePolicy.Always;
});

// 4. JWT Config
var jwtSettings = builder.Configuration.GetSection("JwtSettings");
var secretKey = jwtSettings["Secret"];
if (string.IsNullOrEmpty(secretKey)) throw new Exception("JWT Secret is null!");

var key = Encoding.ASCII.GetBytes(secretKey);

builder.Services.AddAuthentication(options =>
{
    options.DefaultScheme = IdentityConstants.ApplicationScheme;
    options.DefaultSignInScheme = IdentityConstants.ExternalScheme;
})
.AddJwtBearer(options =>
{
    options.RequireHttpsMetadata = false; // Na produkcji zmieniæ na true!
    options.SaveToken = true;
    options.TokenValidationParameters = new TokenValidationParameters
    {
        ValidateIssuerSigningKey = true,
        IssuerSigningKey = new SymmetricSecurityKey(key),
        ValidateIssuer = false, // Warto ustawiæ na true na produkcji i dodaæ "Issuer" w appsettings
        ValidateAudience = false, // Warto ustawiæ na true na produkcji
        ValidateLifetime = true,
        ClockSkew = TimeSpan.Zero
    };
    options.Events = new JwtBearerEvents
    {
        OnMessageReceived = context =>
        {
            if (context.Request.Cookies.ContainsKey("auth_token"))
            {
                context.Token = context.Request.Cookies["auth_token"];
            }
            return Task.CompletedTask;
        }
    };
})
.AddGoogle(options =>
{
    var googleAuth = builder.Configuration.GetSection("Authentication:Google");
    options.ClientId = googleAuth["ClientId"];
    options.ClientSecret = googleAuth["ClientSecret"];
    options.CallbackPath = "/signin-google";
});

// 5. Dependency Injection
builder.Services.AddHttpContextAccessor();
builder.Services.AddControllers();
builder.Services.AddOpenApi();

// Rejestracja serwisów (Clean Architecture)
builder.Services.AddScoped<IUserRepository, UserRepository>();
builder.Services.AddScoped<IAuthService, AuthService>();
builder.Services.AddScoped<IJwtTokenGenerator, JwtTokenGenerator>(); // Nowy serwis!

// 6. CORS
builder.Services.AddCors(options =>
{
    options.AddPolicy("CorsPolicy", policy =>
    {
        // Pobieramy dozwolone origin z konfiguracji
        var frontendUrl = builder.Configuration["FrontendUrl"] ?? "http://localhost:4200";

        policy.AllowAnyHeader()
              .AllowAnyMethod()
              .WithOrigins(frontendUrl)
              .AllowCredentials();
    });
});

var app = builder.Build();

// Pipeline
if (app.Environment.IsDevelopment())
{
    app.MapOpenApi();
    app.MapScalarApiReference();
}

app.UseHttpsRedirection();
app.UseCors("CorsPolicy");

app.UseAuthentication();
app.UseAuthorization();

app.MapControllers();

app.Run();