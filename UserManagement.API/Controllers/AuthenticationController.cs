using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using User.Management.Service.Models;
using User.Management.Service.Services;
using UserManagement.API.Models;
using UserManagement.API.Models.Authentication.Login;
using UserManagement.API.Models.Authentication.SignUp;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using Microsoft.IdentityModel.Tokens;
using System.Text;

namespace UserManagement.API.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class AuthenticationController : ControllerBase
    {
        private readonly UserManager<IdentityUser> _userManager;
        private readonly RoleManager<IdentityRole> _roleManager;
        private readonly IEmailService _emailService;
        private readonly IConfiguration _configuration;

        public AuthenticationController( UserManager<IdentityUser> userManage, 
            RoleManager<IdentityRole> roleManager, 
            IEmailService emailService, 
            IConfiguration configuration)
        {
            _userManager = userManage; 
            _roleManager = roleManager; 
            _emailService = emailService;
            _configuration = configuration;
        }
        [HttpPost]
        public async Task<IActionResult> Register([FromBody] RegisterUser registerUser, string role)
        {
            var _userRegister = await _userManager.FindByEmailAsync(registerUser.Email);
            if(_userRegister != null)
            {
                return StatusCode(StatusCodes.Status403Forbidden, new Response
                {
                    Status = "Error",
                    Message = "User has been existed"
                });
            }
            IdentityUser user = new ()
            {
                Email = registerUser.Email,
                SecurityStamp = Guid.NewGuid().ToString(),
                UserName = registerUser.UserName,
            };
            if(await _roleManager.RoleExistsAsync(role))
            {
                var result = await _userManager.CreateAsync(user, registerUser.Password);
                if (!result.Succeeded)
                {
                    return StatusCode(StatusCodes.Status500InternalServerError, new Response
                    {
                        Status = "Error",
                        Message = "User Failed to Create"
                    });
                }
                // Add role to the user
                await _userManager.AddToRoleAsync(user, role);

                // Add Token to verify the email....
                var token = await _userManager.GenerateEmailConfirmationTokenAsync(user);
                var confirmationLink = Url.Action(nameof(ConfirmEmail), "Authentication", new { token, email = user.Email },Request.Scheme);
                var message = new Message(new string[] { user.Email! }, "Confirmation email link", confirmationLink!);
                _emailService.SendEmail(message);

                return StatusCode(StatusCodes.Status200OK, new Response
                {
                    Status = "Success",
                    Message = "User Created Successfully"
                });
            }
            else
            {
                return StatusCode(StatusCodes.Status500InternalServerError, new Response
                {
                    Status = "Error",
                    Message = "User Failed to Create"
                });
            }
        }
        
        [HttpGet]
        //[ApiExplorerSettings(IgnoreApi = true)]
        public IActionResult TestEmail()
        {
            var message = new Message(new string[] { "bktechcolor@gmail.com" }, "test", "<h1> Subcribe to my channel </h1>");
                _emailService.SendEmail(message);
            return StatusCode( StatusCodes.Status200OK, 
                new Response { Status = "Success", Message = "User Created Successfully" });
        }

        [HttpGet("ConfirmEmail")]
        public async Task<IActionResult> ConfirmEmail(string token, string email)
        {
            var user = await _userManager.FindByEmailAsync(email);
            if(user != null)
            {
                var result = await _userManager.ConfirmEmailAsync(user, token);
                if(result.Succeeded)
                {
                    return StatusCode(StatusCodes.Status200OK, new Response
                    {
                        Status = "Success",
                        Message = "Email Verified Successfully"
                    });
                }
            }
            return StatusCode(StatusCodes.Status500InternalServerError,
                   new Response { Status = "Error", Message = "This User Doesnot exist !" });
        }

        [HttpPost]
        [Route("login")]
        public async Task<IActionResult> Login([FromBody] LoginModel loginModel)
        {
            // checking the user...
            var user = await _userManager.FindByNameAsync(loginModel.UserName);
            // checking the password
            if (user != null && await _userManager.CheckPasswordAsync(user,loginModel.Password))
            {
                // claimlist creation...
                var authClaims = new List<Claim>
                {
                    new Claim(ClaimTypes.Name,user.UserName),
                    new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString())
                };
                // we add roles to the claim...
                var userRoles = await _userManager.GetRolesAsync(user);
                foreach(var role in  userRoles) 
                {
                    authClaims.Add(new Claim(ClaimTypes.Role, role));
                }
                // generate the token with the claims...
                var jwtToken = GetToken(authClaims);
                // returning the token ....
                return Ok(new
                {
                    token = new JwtSecurityTokenHandler().WriteToken(jwtToken),
                    expiration = jwtToken.ValidTo
                });
            }
            return Unauthorized();
        }
        private JwtSecurityToken GetToken(List<Claim> authClaims)
        {
            var authSigninKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_configuration["JWT:Secret"]));
            var token = new JwtSecurityToken(
                issuer: _configuration["JWT:ValidIssuer"],
                audience: _configuration["JWT:ValidAudience"],
                expires: DateTime.Now.AddHours(3),
                claims: authClaims,
                signingCredentials: new SigningCredentials(authSigninKey, SecurityAlgorithms.HmacSha256)
                );
            return token;
        }
    }
}
