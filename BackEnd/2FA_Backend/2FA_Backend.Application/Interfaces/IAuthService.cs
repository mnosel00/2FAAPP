using _2FA_Backend.Domain.DTOs;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace _2FA_Backend.Application.Interfaces
{
    public interface IAuthService
    {
        Task<AuthResult> RegisterUserAsync(RegisterModel model);
        Task<AuthResult> LoginUserAsync(LoginModel model);
        Task<UserProfile?> GetUserProfile(string userId);
        Task<AuthResult> ExternalLoginCallbackAsync();
    }
}
