using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace _2FA_Backend.Domain.DTOs
{
    public class AuthResult
    {
        public bool Success { get; set; }
        public string Token { get; set; }
        public bool Requires2FA { get; set; }
        public string UserId { get; set; }
        public string SetupKey { get; set; }
        public  string QrCodeUrl { get; set; }
        public IEnumerable<string> Errors { get; set; }

    }
}
