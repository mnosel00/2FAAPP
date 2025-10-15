using Microsoft.AspNet.Identity;
using Microsoft.AspNet.Identity.EntityFramework;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace _2FA_Backend.Domain.Interfaces
{
    public interface IUserRepository
    {
        Task<IdentityUser> FindByEmailAsync(string email);
        Task<bool> CheckPasswordAsync(IdentityUser user, string password);
        Task<IdentityResult> CreateAsync(IdentityUser user, string password);
        Task<string> GetAuthenticatorKeyAsync(IdentityUser user);
        Task<IdentityResult> ResetAuthenticatorKeyAsync(IdentityUser user);
        Task<bool> GetTwoFactorEnabledAsync(IdentityUser user);
        Task<IdentityResult> SetTwoFactorEnabledAsync(IdentityUser user, bool enabled);
        Task<IdentityUser> FindByIdAsync(string userId);
        Task<bool> VerifyTwoFactorTokenAsync(IdentityUser user, string tokenProvider, string code);
    }
}
