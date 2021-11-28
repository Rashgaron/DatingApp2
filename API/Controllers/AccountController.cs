using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using API.Data;
using API.DTOs;
using API.Entities;
using DTOs;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;

namespace API.Controllers
{
    [ApiController]
    [Route("api/[controller]")]
    public class AccountController : BaseApiController
    {
        private readonly DataContext _context;
        public AccountController(DataContext context)
        {
            _context = context;
        }
        [HttpPost("login")]
        public async Task<ActionResult<AppUser>> Login(LoginRequest request)
        {
            AppUser user = await _context.Users.FirstOrDefaultAsync(x => x.UserName.Equals(request.UserName.ToLower()));

            if(user == null) return Unauthorized("User does not exists");

            using var hmac = new HMACSHA512(user.PasswordSalt);
            var passwordHash = hmac.ComputeHash(Encoding.UTF8.GetBytes(request.Password));

            for(int i = 0; i < passwordHash.Length; i++) 
            {
                if(passwordHash[i] != user.PasswordHash[i]) return Unauthorized("Invalid password");
            }

            return user;
        } 

        [HttpPost("register")]
        public async Task<ActionResult<AppUser>> Register([FromBody] RegisterRequest request)
        {

            using var hmac = new HMACSHA512();

            var user = new AppUser
            {
                UserName = request.UserName.ToLower(),
                PasswordHash = hmac.ComputeHash(Encoding.UTF8.GetBytes(request.Password)),
                PasswordSalt = hmac.Key
            };

            if(await UserExists(user.UserName)) return BadRequest("UserName is taken");

            _context.Users.Add(user);
            await _context.SaveChangesAsync();

            return user;
        } 

        private async Task<bool> UserExists(string userName)
        {
            return await _context.Users.AnyAsync(x => x.UserName.Equals(userName));
        }

    }
}