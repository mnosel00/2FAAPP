using _2FA_Backend.Application.Interfaces;
using _2FA_Backend.Domain.DTOs;
using _2FA_Backend.Domain.Interfaces;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Configuration;
using Microsoft.IdentityModel.Tokens;
using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Security.Claims;
using System.Text;
using System.Threading.Tasks;

namespace _2FA_Backend.Application.Services
{
    public class AuthService : IAuthService
    {
        private readonly IUserRepository _userRepository;
        private readonly SignInManager<IdentityUser> _signInManager;
        private readonly IConfiguration _configuration;

        public AuthService(IUserRepository userRepository, SignInManager<IdentityUser> signInManager, IConfiguration configuration)
        {
            _userRepository = userRepository;
            _signInManager = signInManager;
            _configuration = configuration;
        }

        public async Task<AuthResult> ExternalLoginCallbackAsync()
        {
            var info = await _signInManager.GetExternalLoginInfoAsync();
            if (info == null)
            {
                return new AuthResult { Errors = new[] { "Błąd podczas pobierania informacji od zewnętrznego dostawcy." } };
            }

            // Spróbuj zalogować użytkownika za pomocą zewnętrznego dostawcy (np. Google)
            var signInResult = await _signInManager.ExternalLoginSignInAsync(info.LoginProvider, info.ProviderKey, isPersistent: false, bypassTwoFactor: true);

            IdentityUser user;
            if (signInResult.Succeeded)
            {
                // Użytkownik już istnieje i ma powiązane konto Google
                user = await _userRepository.FindByLoginAsync(info.LoginProvider, info.ProviderKey);
            }
            else
            {
                // Użytkownik nie ma powiązanego konta lub jest nowy
                var email = info.Principal.FindFirstValue(ClaimTypes.Email);
                if (string.IsNullOrEmpty(email))
                {
                    return new AuthResult { Errors = new[] { "Nie udało się uzyskać adresu e-mail od dostawcy." } };
                }

                user = await _userRepository.FindByEmailAsync(email);
                if (user == null)
                {
                    // Użytkownik nie istnieje, więc tworzymy nowe konto
                    user = new IdentityUser { UserName = email, Email = email, EmailConfirmed = true };
                    var createUserResult = await _userRepository.CreateAsync(user);
                    if (!createUserResult.Succeeded)
                    {
                        return new AuthResult { Errors = createUserResult.Errors.Select(e => e.Description) };
                    }
                }

                // Powiąż konto Google z istniejącym lub nowo utworzonym kontem w naszej bazie
                var addLoginResult = await _userRepository.AddLoginAsync(user, info);
                if (!addLoginResult.Succeeded)
                {
                    return new AuthResult { Errors = addLoginResult.Errors.Select(e => e.Description) };
                }
            }

            // Wygeneruj token JWT dla zalogowanego użytkownika
            var token = GenerateJwtToken(user);
            return new AuthResult { Success = true, Token = token, UserId = user.Id };
        }


        private string GenerateJwtToken(IdentityUser user)
        {
            var jwtSettings = _configuration.GetSection("JwtSettings");
            var key = Encoding.ASCII.GetBytes(jwtSettings["Secret"]);

            var tokenHandler = new JwtSecurityTokenHandler();
            var tokenDescriptor = new SecurityTokenDescriptor
            {
                Subject = new ClaimsIdentity(new[]
                {
                    new Claim(JwtRegisteredClaimNames.Sub, user.Id),
                    new Claim(JwtRegisteredClaimNames.Email, user.Email),
                    new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString())
                }),
                Expires = DateTime.UtcNow.AddHours(1),
                SigningCredentials = new SigningCredentials(new SymmetricSecurityKey(key), SecurityAlgorithms.HmacSha256Signature)
            };

            var token = tokenHandler.CreateToken(tokenDescriptor);
            return tokenHandler.WriteToken(token);
        }

        private string GenerateQrCodeUri(string email, string unformattedKey)
        {
            var issuer = "TwoFactorApp";
            return $"otpauth://totp/{Uri.EscapeDataString(issuer)}:{Uri.EscapeDataString(email)}?secret={unformattedKey}&issuer={Uri.EscapeDataString(issuer)}&digits=6&period=30";
        }

        public Task<string> GetUserProfile(string userId)
        {
            return Task.FromResult($"Witaj na stronie profilowej, użytkowniku o ID: {userId}! Jesteś zalogowany i zweryfikowany.");
        }

        public async Task<AuthResult> LoginUserAsync(LoginModel model)
        {
            var user = await _userRepository.FindByEmailAsync(model.Email);

            if (user == null || !await _userRepository.CheckPasswordAsync(user, model.Password))
            {
                return new AuthResult { Errors = new[] { "Nieprawidłowy login lub hasło." } };
            }

            if (await _userRepository.GetTwoFactorEnabledAsync(user))
            {
                if (string.IsNullOrEmpty(model.TwoFactorCode))
                {
                    // Hasło poprawne, ale wymagany jest kod 2FA
                    return new AuthResult { Success = true, TwoFactorRequired = true, UserId = user.Id };
                }

                var isValidTwoFactor = await _userRepository.VerifyTwoFactorTokenAsync(
                    user,
                    TokenOptions.DefaultAuthenticatorProvider,
                    model.TwoFactorCode
                );

                if (isValidTwoFactor)
                {
                    var token = GenerateJwtToken(user);
                    return new AuthResult { Success = true, Token = token, UserId = user.Id };
                }

                return new AuthResult { Errors = new[] { "Nieprawidłowy kod 2FA." }, TwoFactorRequired = true, UserId = user.Id };
            }

            var loginToken = GenerateJwtToken(user);
            return new AuthResult { Success = true, Token = loginToken, UserId = user.Id };
        }

        public async Task<AuthResult> RegisterUserAsync(RegisterModel model)
        {
            var existingUser = await _userRepository.FindByEmailAsync(model.Email);
            if (existingUser != null)
            {
                return new AuthResult { Errors = new[] { "Użytkownik już istnieje." } };
            }

            var user = new IdentityUser { UserName = model.Email, Email = model.Email, EmailConfirmed = true };
            var result = await _userRepository.CreateAsync(user, model.Password);

            if (result.Succeeded)
            {
                // Włącz 2FA i wygeneruj klucz
                await _userRepository.SetTwoFactorEnabledAsync(user, true);
                var unformattedKey = await _userRepository.GetAuthenticatorKeyAsync(user);
                if (string.IsNullOrEmpty(unformattedKey))
                {
                    await _userRepository.ResetAuthenticatorKeyAsync(user);
                    unformattedKey = await _userRepository.GetAuthenticatorKeyAsync(user);
                }


                var qrCodeUri = GenerateQrCodeUri(user.Email, unformattedKey);

                return new AuthResult
                {
                    Success = true,
                    UserId = user.Id,
                    SetupKey = unformattedKey,
                    QrCodeUri = qrCodeUri
                };
            }

            return new AuthResult { Errors = result.Errors.Select(e => e.Description) };
        }
    }
}
