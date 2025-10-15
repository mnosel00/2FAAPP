using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace _2FA_Backend.Domain.DTOs
{
    public class Verify2FAModel
    {
        public string UserId { get; set; }
        public string Code { get; set; }
    }
}
