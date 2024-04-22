using api.Models;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Text;

namespace api.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class UserController : ControllerBase
    {
        private appContext _appContext;
        private IConfiguration _config;
        public UserController(appContext context, IConfiguration config)
        {
            _appContext = context;
            _config = config; 
        }

        [HttpPost]
        [Route("/register")]
        public async Task<IActionResult> Register([FromBody]user user)
        {
            try
            {
                var res = await _appContext.users.AddAsync(user);
                await _appContext.SaveChangesAsync();
                var securityKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_config["Jwt:Key"]));
                var credentials = new SigningCredentials(securityKey, SecurityAlgorithms.HmacSha256);

                var token = generateToken();
                return Ok(token);
            }
            catch (Exception e)
            {
                Console.WriteLine(e);
                return BadRequest("Server error" + e.ToString());
            }
        }

        [HttpPost]
        [Route("/login")]
        public async Task<IActionResult> Login([FromBody]user user)
        {
            try
            {
                var foundUser = _appContext.users.Where(b => b.email == user.email).FirstOrDefault();
                if (foundUser == null || foundUser.passwordHash != user.passwordHash)
                {
                    return NotFound("User does not exist");
                }

                var token = generateToken();
                return Ok(token);
            }
            catch (Exception e)
            {
                Console.WriteLine(e);
                return Problem(e.ToString());
            }
        }

        private string generateToken()
        {
            var securityKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_config["Jwt:Key"]));
            var credentials = new SigningCredentials(securityKey, SecurityAlgorithms.HmacSha256);

            var Sectoken = new JwtSecurityToken(_config["Jwt:Issuer"],
              _config["Jwt:Issuer"],
              null,
              expires: DateTime.Now.AddMinutes(120),
              signingCredentials: credentials);

            return new JwtSecurityTokenHandler().WriteToken(Sectoken);
        }
    }
}
