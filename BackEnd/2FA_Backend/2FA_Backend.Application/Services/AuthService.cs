using _2FA_Backend.Application.Interfaces;
using _2FA_Backend.Domain.DTOs;
using _2FA_Backend.Domain.Interfaces;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using System.Security.Claims;

namespace _2FA_Backend.Application.Services
{
    public class AuthService : IAuthService
    {
        private readonly IUserRepository _userRepository;
        private readonly SignInManager<IdentityUser> _signInManager;
        private readonly IHttpContextAccessor _httpContextAccessor;
        private readonly IJwtTokenGenerator _jwtTokenGenerator; // Nowa zależność

        public AuthService(
            IUserRepository userRepository,
            SignInManager<IdentityUser> signInManager,
            IHttpContextAccessor httpContextAccessor,
            IJwtTokenGenerator jwtTokenGenerator)
        {
            _userRepository = userRepository;
            _signInManager = signInManager;
            _httpContextAccessor = httpContextAccessor;
            _jwtTokenGenerator = jwtTokenGenerator;
        }

        public async Task<UserProfile?> GetCurrentUserProfileAsync()
        {
            var userId = _httpContextAccessor.HttpContext?.User?.FindFirstValue(ClaimTypes.NameIdentifier);
            if (string.IsNullOrEmpty(userId)) return null;

            return await GetUserProfile(userId);
        }

        public async Task<AuthResult> ExternalLoginCallbackAsync()
        {
            var info = await _signInManager.GetExternalLoginInfoAsync();
            if (info == null)
                return new AuthResult { Errors = new[] { "Błąd zewnętrznego dostawcy." } };

            // Próba logowania
            var signInResult = await _signInManager.ExternalLoginSignInAsync(info.LoginProvider, info.ProviderKey, isPersistent: false, bypassTwoFactor: true);

            IdentityUser? user = null;

            if (signInResult.Succeeded)
            {
                user = await _userRepository.FindByLoginAsync(info.LoginProvider, info.ProviderKey);
            }
            else
            {
                // Rejestracja nowego użytkownika z Google
                var email = info.Principal.FindFirstValue(ClaimTypes.Email);
                if (string.IsNullOrEmpty(email))
                    return new AuthResult { Errors = new[] { "Brak adresu email od dostawcy." } };

                user = await _userRepository.FindByEmailAsync(email);

                if (user == null)
                {
                    user = new IdentityUser { UserName = email, Email = email, EmailConfirmed = true };
                    var createResult = await _userRepository.CreateAsync(user);
                    if (!createResult.Succeeded)
                        return new AuthResult { Errors = createResult.Errors.Select(e => e.Description) };
                }

                var addLoginResult = await _userRepository.AddLoginAsync(user, info);
                if (!addLoginResult.Succeeded)
                    return new AuthResult { Errors = addLoginResult.Errors.Select(e => e.Description) };
            }

            if (user == null)
                return new AuthResult { Errors = new[] { "Błąd logowania." } };

            var token = _jwtTokenGenerator.GenerateToken(user);
            return new AuthResult { Success = true, Token = token, UserId = user.Id };
        }

        public async Task<UserProfile?> GetUserProfile(string userId)
        {
            var user = await _userRepository.FindByIdAsync(userId);
            return user == null ? null : new UserProfile { UserId = user.Id, Email = user.Email };
        }

        public async Task<AuthResult> LoginUserAsync(LoginModel model)
        {
            var user = await _userRepository.FindByEmailAsync(model.Email);

            // SECURITY: Generic error message to prevent User Enumeration
            if (user == null || !await _userRepository.CheckPasswordAsync(user, model.Password))
            {
                return new AuthResult { Errors = new[] { "Nieprawidłowe dane logowania." } };
            }

            // 2FA Logic
            if (await _userRepository.GetTwoFactorEnabledAsync(user))
            {
                if (string.IsNullOrEmpty(model.TwoFactorCode))
                {
                    return new AuthResult { Success = true, TwoFactorRequired = true, UserId = user.Id };
                }

                var isValidTwoFactor = await _userRepository.VerifyTwoFactorTokenAsync(
                    user,
                    TokenOptions.DefaultAuthenticatorProvider,
                    model.TwoFactorCode
                );

                if (!isValidTwoFactor)
                {
                    return new AuthResult { Errors = new[] { "Nieprawidłowy kod 2FA." }, TwoFactorRequired = true, UserId = user.Id };
                }
            }

            var token = _jwtTokenGenerator.GenerateToken(user);
            return new AuthResult { Success = true, Token = token, UserId = user.Id };
        }

        public async Task<AuthResult> RegisterUserAsync(RegisterModel model)
        {
            // Sprawdzenie czy istnieje
            var existingUser = await _userRepository.FindByEmailAsync(model.Email);
            if (existingUser != null)
            {
                return new AuthResult { Errors = new[] { "Użytkownik o podanym adresie już istnieje." } };
            }

            var user = new IdentityUser { UserName = model.Email, Email = model.Email, EmailConfirmed = true };
            var result = await _userRepository.CreateAsync(user, model.Password);

            if (!result.Succeeded)
            {
                return new AuthResult { Errors = result.Errors.Select(e => e.Description) };
            }

            // Setup 2FA
            await _userRepository.SetTwoFactorEnabledAsync(user, true);
            var unformattedKey = await _userRepository.GetAuthenticatorKeyAsync(user);

            if (string.IsNullOrEmpty(unformattedKey))
            {
                await _userRepository.ResetAuthenticatorKeyAsync(user);
                unformattedKey = await _userRepository.GetAuthenticatorKeyAsync(user);
            }

            // Generowanie URI do kodu QR przeniesione do metody prywatnej lub helpera, 
            // ale tutaj zostawiam lokalnie dla czytelności serwisu.
            var qrCodeUri = GenerateQrCodeUri(user.Email!, unformattedKey!);

            return new AuthResult
            {
                Success = true,
                UserId = user.Id,
                SetupKey = unformattedKey,
                QrCodeUri = qrCodeUri
            };
        }

        // Metody ResetPassword i ChangePassword zostawiam bez zmian logicznych, 
        // są poprawne, pamiętaj tylko o weryfikacji usera.

        public async Task<AuthResult> ResetPasswordAsync(ResetPasswordModel model)
        {
            var user = await _userRepository.FindByEmailAsync(model.Email);
            // SECURITY: Zawsze zwracaj sukces, nawet jeśli email nie istnieje, żeby nie zdradzać bazy.
            // W tym przypadku (Reset z tokenem 2FA) musimy jednak poinformować o błędnym tokenie.
            if (user == null) return new AuthResult { Errors = new[] { "Nieprawidłowe dane." } };

            var isTokenValid = await _userRepository.VerifyTwoFactorTokenAsync(user, TokenOptions.DefaultAuthenticatorProvider, model.Token);
            if (!isTokenValid) return new AuthResult { Errors = new[] { "Nieprawidłowy kod weryfikacyjny." } };

            var resetToken = await _userRepository.GeneratePasswordResetTokenAsync(user);
            var result = await _userRepository.ResetPasswordAsync(user, resetToken, model.NewPassword);

            return result.Succeeded
                ? new AuthResult { Success = true }
                : new AuthResult { Errors = result.Errors.Select(e => e.Description) };
        }

        public async Task<AuthResult> ChangePasswordAsync(ChangePasswordModel model)
        {
            var userId = _httpContextAccessor.HttpContext?.User?.FindFirstValue(ClaimTypes.NameIdentifier);
            if (userId == null) return new AuthResult { Errors = new[] { "Błąd autoryzacji." } };

            var user = await _userRepository.FindByIdAsync(userId);
            if (user == null) return new AuthResult { Errors = new[] { "Nie znaleziono użytkownika." } };

            var result = await _userRepository.ChangePasswordAsync(user, model.OldPassword, model.NewPassword);

            return result.Succeeded
                ? new AuthResult { Success = true }
                : new AuthResult { Errors = result.Errors.Select(e => e.Description) };
        }

        private string GenerateQrCodeUri(string email, string unformattedKey)
        {
            const string issuer = "TwoFactorApp";
            return $"otpauth://totp/{Uri.EscapeDataString(issuer)}:{Uri.EscapeDataString(email)}?secret={unformattedKey}&issuer={Uri.EscapeDataString(issuer)}&digits=6&period=30";
        }
    }
}