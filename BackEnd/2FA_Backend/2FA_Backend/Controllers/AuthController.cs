using _2FA_Backend.Application.Interfaces;
using _2FA_Backend.Domain.DTOs;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Google;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity; // Potrzebne tylko do nazw schematów, nie logiki
using Microsoft.AspNetCore.Mvc;

namespace _2FA_Backend.Controllers
{
    [ApiController]
    [Route("api/[controller]")]
    public class AuthController : ControllerBase // Zmiana z Controller na ControllerBase (lżejsze dla API)
    {
        private readonly IAuthService _authService;
        private readonly IConfiguration _configuration;

        // Nie wstrzykujemy już SignInManager! Kontroler ma o nim nie wiedzieć.
        public AuthController(IAuthService authService, IConfiguration configuration)
        {
            _authService = authService;
            _configuration = configuration;
        }

        [Authorize]
        [HttpGet("profile")]
        public async Task<ActionResult<UserProfile>> GetCurrentUserProfile()
        {
            var profileInfo = await _authService.GetCurrentUserProfileAsync();
            if (profileInfo == null) return Unauthorized(new { Message = "Nie udało się zidentyfikować użytkownika." });

            return Ok(profileInfo);
        }

        [HttpPost("register")]
        public async Task<IActionResult> Register([FromBody] RegisterModel model)
        {
            var result = await _authService.RegisterUserAsync(model);
            if (!result.Success) return BadRequest(new { Errors = result.Errors });

            return Ok(new { result.UserId, result.SetupKey, result.QrCodeUri });
        }

        [HttpPost("login")]
        public async Task<IActionResult> Login([FromBody] LoginModel model)
        {
            var result = await _authService.LoginUserAsync(model);

            if (!result.Success)
            {
                // Jeśli wymagane jest 2FA, zwracamy specyficzny status, ale bez tokena
                if (result.TwoFactorRequired)
                    return Unauthorized(new { TwoFactorRequired = true, UserId = result.UserId });

                return Unauthorized(new { Errors = result.Errors });
            }

            // DRY: Użycie metody pomocniczej
            if (!string.IsNullOrEmpty(result.Token))
            {
                SetTokenCookie(result.Token);
            }

            return Ok(new { UserId = result.UserId });
        }

        [HttpPost("logout")]
        public IActionResult Logout()
        {
            DeleteTokenCookie();
            return Ok(new { Message = "Wylogowano pomyślnie." });
        }

        // --- Google Auth ---

        [HttpGet("google-login")]
        public IActionResult GoogleLogin()
        {
            var redirectUrl = Url.Action(nameof(GoogleCallback));
            var properties = new AuthenticationProperties { RedirectUri = redirectUrl };
            return Challenge(properties, GoogleDefaults.AuthenticationScheme);
        }

        [HttpGet("google-callback")]
        public async Task<IActionResult> GoogleCallback()
        {
            var result = await _authService.ExternalLoginCallbackAsync();

            var frontendUrl = _configuration["FrontendUrl"] ?? "http://localhost:4200";

            if (result.Success && !string.IsNullOrEmpty(result.Token))
            {
                SetTokenCookie(result.Token);
                return Redirect($"{frontendUrl}/login-success?userId={result.UserId}");
            }

            return Redirect($"{frontendUrl}/login-failed");
        }

        [HttpPost("reset-password")]
        public async Task<IActionResult> ResetPassword(ResetPasswordModel model)
        {
            if (!ModelState.IsValid) return BadRequest(ModelState);

            var result = await _authService.ResetPasswordAsync(model);
            if (!result.Success) return BadRequest(result);

            return Ok(new { message = "Hasło zostało pomyślnie zresetowane." });
        }

        [Authorize]
        [HttpPost("change-password")]
        public async Task<IActionResult> ChangePassword(ChangePasswordModel model)
        {
            if (!ModelState.IsValid) return BadRequest(ModelState);

            var result = await _authService.ChangePasswordAsync(model);
            if (!result.Success) return BadRequest(result);

            return Ok(new { message = "Hasło zostało pomyślnie zmienione." });
        }

        // --- PRIVATE HELPERS (DRY & KISS) ---

        private void SetTokenCookie(string token)
        {
            var cookieOptions = new CookieOptions
            {
                HttpOnly = true,
                Secure = true, // Wymagane na produkcji (HTTPS)
                SameSite = SameSiteMode.None,
                Expires = DateTime.UtcNow.AddHours(1)
            };
            Response.Cookies.Append("auth_token", token, cookieOptions);
        }

        private void DeleteTokenCookie()
        {
            var cookieOptions = new CookieOptions
            {
                HttpOnly = true,
                Secure = true,
                SameSite = SameSiteMode.None
            };
            Response.Cookies.Delete("auth_token", cookieOptions);
        }
    }
}