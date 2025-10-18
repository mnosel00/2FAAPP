using _2FA_Backend.Application.Interfaces;
using _2FA_Backend.Domain.DTOs;
using Microsoft.AspNetCore.Mvc;

namespace _2FA_Backend.Controllers
{
    [ApiController]
    [Route("api/[controller]")]
    public class AuthController : Controller
    {
        private readonly IAuthService _authService;

        public AuthController(IAuthService authService) 
        {
            _authService = authService;
        }

        [HttpPost("register")]
        public async Task<IActionResult> Register([FromBody] RegisterModel model)
        {
            var result = await _authService.RegisterUserAsync(model);

            if (result.Success)
            {
                // Zwraca UserId, SetupKey i QrCodeUri do konfiguracji 2FA
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
                    // Użytkownik musi podać kod 2FA w kolejnym żądaniu do tego samego endpointu
                    return Ok(new { TwoFactorRequired = true, UserId = result.UserId });
                }
                // Logowanie pomyślne
                return Ok(new { Token = result.Token, UserId = result.UserId });
            }

            // Jeśli logowanie nie powiodło się (np. zły kod 2FA), zwróć błąd
            if (result.TwoFactorRequired)
            {
                return Unauthorized(new { Errors = result.Errors, TwoFactorRequired = true, UserId = result.UserId });
            }

            return Unauthorized(new { Errors = result.Errors });
        }


        [HttpGet("profile/{userId}")]
        public async Task<IActionResult> GetProfile(string userId)
        {
            var profileInfo = await _authService.GetUserProfile(userId);
            return Ok(new { Message = profileInfo });
        }
    }
}

