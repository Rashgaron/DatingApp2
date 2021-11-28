using System.ComponentModel.DataAnnotations;

namespace DTOs
{
    public class LoginRequest
    {
        [Required]
        public string UserName { get; set; }    
        [Required]
        public string Password { get; set; }
    }
}