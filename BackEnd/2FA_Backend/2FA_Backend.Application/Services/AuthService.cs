using _2FA_Backend.Application.Interfaces;
using _2FA_Backend.Domain.DTOs;
using _2FA_Backend.Domain.Interfaces;
using Microsoft.AspNetCore.Identity;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace _2FA_Backend.Application.Services
{
    public class AuthService : IAuthService
    {
        private readonly IUserRepository _userRepository;

        public AuthService(IUserRepository userRepository)
        {
            _userRepository = userRepository;
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
                    return new AuthResult { Success = true, Token = $"REAL_JWT_TOKEN_{user.Id}", UserId = user.Id };
                }

                return new AuthResult { Errors = new[] { "Nieprawidłowy kod 2FA." }, TwoFactorRequired = true, UserId = user.Id };
            }

            // Logika tymczasowego tokenu, jeśli nie ma 2FA
            var token = $"FAKE_JWT_TOKEN_{user.Id}";
            return new AuthResult { Success = true, Token = token, UserId = user.Id };
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
