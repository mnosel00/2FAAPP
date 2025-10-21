using _2FA_Backend.Application.Interfaces;
using _2FA_Backend.Domain.DTOs;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Google;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;

namespace _2FA_Backend.Controllers
{
    [ApiController]
    [Route("api/[controller]")]
    public class AuthController : Controller
    {
        private readonly IAuthService _authService;
        private readonly SignInManager<IdentityUser> _signInManager;

        // KROK 1: Upewnij się, że SignInManager jest wstrzykiwany do konstruktora
        public AuthController(IAuthService authService, SignInManager<IdentityUser> signInManager)
        {
            _authService = authService;
            _signInManager = signInManager;
        }

        [Authorize] // Ten atrybut zapewnia, że tylko zalogowani użytkownicy mogą uzyskać dostęp
        [HttpGet("profile")]
        public async Task<IActionResult> GetCurrentUserProfile()
        {
            var profileInfo = await _authService.GetCurrentUserProfileAsync();
            if (profileInfo == null)
            {
                return Unauthorized(new { Message = "Nie udało się zidentyfikować użytkownika." });
            }
            return Ok(profileInfo);
        }

        [HttpPost("register")]
        public async Task<IActionResult> Register([FromBody] RegisterModel model)
        {
            var result = await _authService.RegisterUserAsync(model);

            if (result.Success)
            {
                return Ok(new
                {
                    result.UserId,
                    result.SetupKey,
                    result.QrCodeUri
                });
            }

            return BadRequest(new { Errors = result.Errors });
        }

        [HttpPost("login")]
        public async Task<IActionResult> Login([FromBody] LoginModel model)
        {
            var result = await _authService.LoginUserAsync(model);

            if (result.Success)
            {
                if (result.TwoFactorRequired)
                {
                    return Ok(new { TwoFactorRequired = true, UserId = result.UserId });
                }

                if (!string.IsNullOrEmpty(result.Token))
                {
                    Response.Cookies.Append("auth_token", result.Token, new CookieOptions
                    {
                        HttpOnly = true,
                        Secure = true,
                        SameSite = SameSiteMode.None, // Wymagane dla cross-origin
                        Expires = DateTime.UtcNow.AddHours(1)
                    });
                }
                return Ok(new { UserId = result.UserId });
            }

            if (result.TwoFactorRequired)
            {
                return Unauthorized(new { Errors = result.Errors, TwoFactorRequired = true, UserId = result.UserId });
            }

            return Unauthorized(new { Errors = result.Errors });
        }

        [HttpPost("logout")]
        public IActionResult Logout()
        {
            Response.Cookies.Delete("auth_token", new CookieOptions
            {
                HttpOnly = true,
                Secure = true,
                SameSite = SameSiteMode.None
            });
            return Ok(new { Message = "Wylogowano pomyślnie." });
        }

        [HttpGet("profile/{userId}")]
        public async Task<IActionResult> GetProfile(string userId)
        {
            var profileInfo = await _authService.GetUserProfile(userId);

            if (profileInfo == null)
            {
                return NotFound(new { Message = "Użytkownik nie znaleziony." });
            }

            return Ok(profileInfo);
        }

        [HttpGet("google-login")]
        public IActionResult GoogleLogin()
        {
            // KROK 2: Używamy SignInManager do poprawnego skonfigurowania właściwości
            // Ta metoda tworzy bezpieczne ciasteczko korelacji, którego teraz brakuje.
            var redirectUrl = Url.Action(nameof(GoogleCallback));
            var properties = _signInManager.ConfigureExternalAuthenticationProperties(GoogleDefaults.AuthenticationScheme, redirectUrl);
            return Challenge(properties, GoogleDefaults.AuthenticationScheme);
        }

        [HttpGet("google-callback")]
        public async Task<IActionResult> GoogleCallback()
        {
            var result = await _authService.ExternalLoginCallbackAsync();

            if (result.Success && !string.IsNullOrEmpty(result.Token))
            {
                Response.Cookies.Append("auth_token", result.Token, new CookieOptions
                {
                    HttpOnly = true,
                    Secure = true,
                    // KROK 3: SameSite.None jest niezbędne, aby przeglądarka zapisała ciasteczko
                    SameSite = SameSiteMode.None,
                    Expires = DateTime.UtcNow.AddHours(1)
                });
                return Redirect($"http://localhost:4200/login-success?userId={result.UserId}");
            }

            return Redirect("http://localhost:4200/login-failed");
        }
    }
}

