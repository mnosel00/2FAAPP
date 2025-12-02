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
using System.Diagnostics;
using System.Text;

var builder = WebApplication.CreateBuilder(args);

// Add services to the container.

builder.Services.AddControllers();
// Learn more about configuring OpenAPI at https://aka.ms/aspnet/openapi
builder.Services.AddOpenApi();
builder.Services.AddHttpContextAccessor();

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
builder.Services.ConfigureExternalCookie(options =>
{
    options.Cookie.SameSite = SameSiteMode.None;
    options.Cookie.SecurePolicy = CookieSecurePolicy.Always;
});

var jwtSettings = builder.Configuration.GetSection("JwtSettings");
var key = Encoding.ASCII.GetBytes(jwtSettings["Secret"]);

builder.Services.AddAuthentication(options =>
{
    // --- ZMIANA 1: Ustawiamy JWT jako domyœlny schemat dla API ---
    // Schematy Identity bêd¹ u¿ywane tylko w razie potrzeby (np. przy logowaniu Google)
    options.DefaultAuthenticateScheme = JwtBearerDefaults.AuthenticationScheme;
    options.DefaultChallengeScheme = JwtBearerDefaults.AuthenticationScheme;
})
.AddJwtBearer(options =>
{
    // --- ZMIANA 2: Poprawiamy walidacjê tokenu ---
    options.SaveToken = true;
    options.TokenValidationParameters = new TokenValidationParameters
    {
        ValidateIssuer = true,
        ValidateAudience = true,
        ValidateLifetime = true,
        ValidateIssuerSigningKey = true,
        ValidIssuer = builder.Configuration["JwtSettings:Issuer"], // POPRAWKA
        ValidAudience = builder.Configuration["JwtSettings:Audience"], // POPRAWKA
        IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(builder.Configuration["JwtSettings:Secret"])) // POPRAWKA
    };
    // Odczytywanie tokenu z ciasteczka - to ju¿ masz poprawnie
    options.Events = new JwtBearerEvents
    {
        OnMessageReceived = context =>
        {
            var accessToken = context.Request.Cookies["auth_token"];

            // LOGOWANIE DIAGNOSTYCZNE
            if (string.IsNullOrEmpty(accessToken))
            {
                Debug.WriteLine(">>> [DEBUG] Brak ciasteczka 'auth_token' w ¿¹daniu!");
            }
            else
            {
                Debug.WriteLine($">>> [DEBUG] Znaleziono ciasteczko 'auth_token'. D³ugoœæ: {accessToken.Length}");
                context.Token = accessToken;
            }
            return Task.CompletedTask;
        },
        OnAuthenticationFailed = context =>
        {
            // TO POKA¯E DLACZEGO TOKEN JEST ODRZUCANY
            Debug.WriteLine($">>> [DEBUG] B³¹d walidacji tokenu: {context.Exception.Message}");
            return Task.CompletedTask;
        },
        OnTokenValidated = context =>
        {
            Debug.WriteLine(">>> [DEBUG] Token poprawny!");
            return Task.CompletedTask;
        }
    };
})
.AddGoogle(options =>
 {
     var googleAuthNSection = builder.Configuration.GetSection("Authentication:Google");
     options.ClientId = googleAuthNSection["ClientId"];
     options.ClientSecret = googleAuthNSection["ClientSecret"];
     options.CallbackPath = "/signin-google";

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
