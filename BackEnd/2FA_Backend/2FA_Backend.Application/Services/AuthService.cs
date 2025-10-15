using _2FA_Backend.Application.Interfaces;
using _2FA_Backend.Domain.DTOs;
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
        private readonly UserManager<IdentityUser> _userManager;

        public AuthService(UserManager<IdentityUser> userManager)
        {
            _userManager = userManager;
        }

        public Task<AuthResult> LoginUserAsync(LoginModel model)
        {
            throw new NotImplementedException();
        }

        public Task<AuthResult> RegisterUserAsync(RegisterModel model)
        {
            throw new NotImplementedException();
        }

        public Task<AuthResult> Verify2FAAsync(string userId, string code)
        {
            throw new NotImplementedException();
        }
    }
}
