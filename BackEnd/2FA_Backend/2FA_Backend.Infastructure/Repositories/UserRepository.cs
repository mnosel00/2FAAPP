using _2FA_Backend.Domain.Interfaces;
using Microsoft.AspNetCore.Identity;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace _2FA_Backend.Infastructure.Repositories
{

    public class UserRepository : IUserRepository
    {
        private readonly UserManager<IdentityUser> _userManager;

        public UserRepository(UserManager<IdentityUser> userManager)
        {
            _userManager = userManager;
        }

        public Task<IdentityResult> AddLoginAsync(IdentityUser user, UserLoginInfo info)
        {
            throw new NotImplementedException();
        }

        public Task<bool> CheckPasswordAsync(IdentityUser user, string password) =>
         _userManager.CheckPasswordAsync(user, password);

        public Task<IdentityResult> CreateAsync(IdentityUser user, string password) =>
         _userManager.CreateAsync(user, password);

        public Task<IdentityResult> CreateAsync(IdentityUser user)
        {
            throw new NotImplementedException();
        }

        public Task<IdentityUser> FindByEmailAsync(string email) =>
            _userManager.FindByEmailAsync(email);

        public Task<IdentityUser> FindByIdAsync(string userId) =>
             _userManager.FindByIdAsync(userId);

        public Task<IdentityUser> FindByLoginAsync(string loginProvider, string providerKey)
        {
            throw new NotImplementedException();
        }

        public Task<string> GetAuthenticatorKeyAsync(IdentityUser user) =>
         _userManager.GetAuthenticatorKeyAsync(user);

        public Task<bool> GetTwoFactorEnabledAsync(IdentityUser user) =>
             _userManager.GetTwoFactorEnabledAsync(user);

        public Task<IdentityResult> ResetAuthenticatorKeyAsync(IdentityUser user) =>
            _userManager.ResetAuthenticatorKeyAsync(user);

        public Task<IdentityResult> SetTwoFactorEnabledAsync(IdentityUser user, bool enabled) =>
             _userManager.SetTwoFactorEnabledAsync(user, enabled);

        public Task<bool> VerifyTwoFactorTokenAsync(IdentityUser user, string tokenProvider, string code) =>
         _userManager.VerifyTwoFactorTokenAsync(user, tokenProvider, code);
    }
}
