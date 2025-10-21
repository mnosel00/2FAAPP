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

// Add services to the container.

builder.Services.AddControllers();
// Learn more about configuring OpenAPI at https://aka.ms/aspnet/openapi
builder.Services.AddOpenApi();

builder.Services.AddDbContext<ApplicationDbContext>(options =>
    options.UseSqlServer(builder.Configuration.GetConnectionString("DefaultConnection")));

builder.Services.AddIdentity<IdentityUser, IdentityRole>(options =>
{
    options.Tokens.AuthenticatorTokenProvider = TokenOptions.DefaultAuthenticatorProvider;
})
    .AddEntityFrameworkStores<ApplicationDbContext>()
    .AddDefaultTokenProviders();

// --- KLUCZOWA ZMIANA: Konfiguracja ciasteczek dla Identity ---
builder.Services.ConfigureApplicationCookie(options =>
{
    // Ustawiamy SameSite=None, aby ciasteczka dzia³a³y miêdzy backendem a frontendem na ró¿nych portach.
    options.Cookie.SameSite = SameSiteMode.None;
    options.Cookie.SecurePolicy = CookieSecurePolicy.Always; // Wymaga HTTPS
    options.Cookie.HttpOnly = true;

    // Zapobiegamy automatycznemu przekierowaniu do strony logowania, co jest typowe dla API.
    options.Events.OnRedirectToLogin = context =>
    {
        context.Response.StatusCode = StatusCodes.Status401Unauthorized;
        return Task.CompletedTask;
    };
});

var jwtSettings = builder.Configuration.GetSection("JwtSettings");
var key = Encoding.ASCII.GetBytes(jwtSettings["Secret"]);

builder.Services.AddAuthentication(options =>
{
    // Ustawiamy domyœlny schemat na ten u¿ywany przez Identity (oparty na ciasteczkach).
    // To jest niezbêdne, aby logowanie zewnêtrzne (Google) dzia³a³o poprawnie.
    options.DefaultScheme = IdentityConstants.ApplicationScheme;
    options.DefaultSignInScheme = IdentityConstants.ExternalScheme;
})
.AddJwtBearer(options =>
{
    options.RequireHttpsMetadata = false;
    options.SaveToken = true;
    options.TokenValidationParameters = new TokenValidationParameters
    {
        ValidateIssuerSigningKey = true,
        IssuerSigningKey = new SymmetricSecurityKey(key),
        ValidateIssuer = false,
        ValidateAudience = false
    };
    // Odczytywanie tokenu z ciasteczka
    options.Events = new JwtBearerEvents
    {
        OnMessageReceived = context =>
        {
            context.Token = context.Request.Cookies["auth_token"];
            return Task.CompletedTask;
        }
    };
})
.AddGoogle(options =>
 {
     var googleAuthNSection = builder.Configuration.GetSection("Authentication:Google");
     options.ClientId = googleAuthNSection["ClientId"];
     options.ClientSecret = googleAuthNSection["ClientSecret"];
     // Po zalogowaniu Google przekieruje z powrotem na ten adres
     options.CallbackPath = "/api/auth/google-callback";
 });

builder.Services.AddScoped<IUserRepository, UserRepository>();
builder.Services.AddScoped<IAuthService, AuthService>();

builder.Services.AddCors(options =>
{
    options.AddPolicy("CorsPolicy", policy =>
    {
        policy.AllowAnyHeader()
              .AllowAnyMethod()
              .WithOrigins("http://localhost:4200")
              .AllowCredentials();
    });
});

var app = builder.Build();

// Configure the HTTP request pipeline.
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
