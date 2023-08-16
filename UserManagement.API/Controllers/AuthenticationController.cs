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
using Microsoft.AspNetCore.Authorization;
using System.ComponentModel.DataAnnotations;

namespace UserManagement.API.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class AuthenticationController : ControllerBase
    {
        private readonly UserManager<IdentityUser> _userManager;
        private readonly SignInManager<IdentityUser> _signInManager;
        private readonly RoleManager<IdentityRole> _roleManager;
        private readonly IEmailService _emailService;
        private readonly IConfiguration _configuration;

        public AuthenticationController( UserManager<IdentityUser> userManage, 
            RoleManager<IdentityRole> roleManager, 
            IEmailService emailService, 
            SignInManager<IdentityUser> signInManager,
            IConfiguration configuration
            )
        {
            _userManager = userManage; 
            _roleManager = roleManager;
            _signInManager = signInManager; 
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
                // add 2FA function
                TwoFactorEnabled = true
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

                // Add Token to verify the email
                var token = await _userManager.GenerateEmailConfirmationTokenAsync(user);
                var confirmationLink = Url.Action(nameof(ConfirmEmail), "Authentication", new { token, email = user.Email },Request.Scheme);
                var message = new Message(new string[] { user.Email! }, "Confirmation email link", confirmationLink!);
                _emailService.SendEmail(message);

                return StatusCode(StatusCodes.Status200OK, new Response
                {
                    Status = "Success",
                    Message = "User created successfully !"
                });
            }
            else
            {
                return StatusCode(StatusCodes.Status500InternalServerError, new Response
                {
                    Status = "Error",
                    Message = "User failed to create"
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
                new Response { Status = "Success", Message = "User created successfully" });
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

            // Still not check User verification here
            //..............
            // Check 2FA
            if (user.TwoFactorEnabled)
            {
                await _signInManager.SignOutAsync();
                await _signInManager.PasswordSignInAsync(user, loginModel.Password, false, true);
                var token = await _userManager.GenerateTwoFactorTokenAsync(user, "Email");
                var message = new Message(new string[] { user.Email! }, "OTP Token for verification", token!);
                _emailService.SendEmail(message);
                return StatusCode(StatusCodes.Status200OK,
                    new Response { Status = "Success", Message = $"We have sent OTP to your email {user.Email}" });
            }
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

        [HttpPost]
        [Route("login-2FA")]
        public async Task<IActionResult> LoginWithOTP(string code, string username)
        {
            var user = await _userManager.FindByNameAsync(username);
            var signIn = await _signInManager.TwoFactorSignInAsync("Email", code, false, false);
            if (signIn.Succeeded)
            {
                if (user != null )
                {
                    // claimlist creation...
                    var authClaims = new List<Claim>
                {
                    new Claim(ClaimTypes.Name,user.UserName),
                    new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString())
                };
                    // we add roles to the claim...
                    var userRoles = await _userManager.GetRolesAsync(user);
                    foreach (var role in userRoles)
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
            }
            return StatusCode(StatusCodes.Status404NotFound, new Response
            {
                Status = "Success",
                Message = "Invalid Code"
            });
        }

        [HttpPost]
        [AllowAnonymous]
        [Route("forgot-password")]
        public async Task<IActionResult> ForgotPassword([Required] string email)
        {
            var user = await _userManager.FindByEmailAsync(email);
            if(user !=null)
            {
                var token = await _userManager.GeneratePasswordResetTokenAsync(user);
                var forgotPasswordLink = Url.Action(nameof(ResetPassword), "Authentication", new { token, email = user.Email }, Request.Scheme);
                var message = new Message(new string[] { user.Email! }, "Forgot Password link", forgotPasswordLink!);
                _emailService.SendEmail(message);
                return StatusCode(StatusCodes.Status200OK,
                    new Response { Status = "Success",Message = $"Password Changed request is sent on Email {user.Email}.Please open your email and follow the link !"});
            }
            return StatusCode(StatusCodes.Status400BadRequest,
                    new Response { Status = "Error", Message = $"Could not send link to email, please try again." });
        }
        [HttpGet("reset-password")]
        [AllowAnonymous]
        public async Task<IActionResult> ResetPassword(string token, string email)
        {
            var model = new ResetPassword { Token = token, Email = email };
            return Ok(new
            {
                model
            });
        }
        [HttpPost]
        [AllowAnonymous]
        [Route("reset-password")]
        public async Task<IActionResult> ResetPassword(ResetPassword resetPassword)
        {
            var user = await _userManager.FindByEmailAsync(resetPassword.Email);
            if (user != null)
            {
                var resetPasswordResult = await _userManager.ResetPasswordAsync(user, resetPassword.Token, resetPassword.Password);
                if(!resetPasswordResult.Succeeded)
                {
                    foreach(var error in resetPasswordResult.Errors)
                    {
                        ModelState.AddModelError(error.Code, error.Description);
                    }
                    return Ok(ModelState);
                }
                return StatusCode(StatusCodes.Status200OK,
                    new Response { Status = "Success", Message = $"Password has been changed" });
            }
            return StatusCode(StatusCodes.Status400BadRequest,
                    new Response { Status = "Error", Message = $"Could not send link to email, please try again." });
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
