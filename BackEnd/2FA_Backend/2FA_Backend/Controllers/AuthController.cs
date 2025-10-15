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
                // Zwraca SetupKey i QrCodeUri
                return Ok(result);
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
                return Ok(new { Token = result.Token });
            }

            return Unauthorized(new { Errors = result.Errors });
        }

        [HttpPost("verify2fa")]
        public async Task<IActionResult> Verify2FA([FromBody] Verify2FAModel model)
        {
            var result = await _authService.Verify2FACodeAsync(model);

            if (result.Success)
            {
                return Ok(new { Token = result.Token });
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

