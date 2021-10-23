using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Security.Claims;
using System.Text;
using System.Threading.Tasks;
using AutoMapper;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;
using Microsoft.IdentityModel.Tokens;
using WIMP_Server.Dtos.Users;
using WIMP_Server.Models.Users;

namespace WIMP_Server.Controllers
{
    [ApiController]
    [Route("[controller]")]
    [Authorize(AuthenticationSchemes = JwtBearerDefaults.AuthenticationScheme)]
    public class UserController : ControllerBase
    {
        public UserController(UserManager<User> userManager, RoleManager<IdentityRole> roleManager, IConfiguration configuration, IMapper mapper, ILogger<UserController> logger)
        {
            _userManager = userManager;
            _roleManager = roleManager;
            _configuration = configuration;
            _mapper = mapper;
            _logger = logger;
        }

        private readonly UserManager<User> _userManager;
        private readonly RoleManager<IdentityRole> _roleManager;
        private readonly IConfiguration _configuration;
        private readonly IMapper _mapper;
        private readonly ILogger<UserController> _logger;

        [HttpPost("register")]
        [ProducesResponseType(StatusCodes.Status201Created)]
        [ProducesResponseType(StatusCodes.Status400BadRequest)]
        [ProducesResponseType(StatusCodes.Status409Conflict)]
        [AllowAnonymous]
        public async Task<ActionResult<ReadUserDto>> Register([FromBody] RegisterUserDto registerUserDto)
        {
            var existingUser = await _userManager
                .FindByNameAsync(registerUserDto.Username)
                .ConfigureAwait(true);
            if (existingUser != null)
            {
                return Conflict($"User with {registerUserDto.Username} already exists.");
            }

            var user = _mapper.Map<User>(registerUserDto);

            var createUserResult = await _userManager
                .CreateAsync(user, registerUserDto.Password)
                .ConfigureAwait(true);
            if (!createUserResult.Succeeded)
            {
                return BadRequest("Failed to register user");
            }

            _logger.LogInformation($"Registered user with id {user.Id} and username {user.UserName}");

            var readUserDto = _mapper.Map<ReadUserDto>(user);

            return CreatedAtRoute(nameof(GetUserById), new { readUserDto.Id }, readUserDto);
        }

        [HttpPost("login")]
        [ProducesResponseType(StatusCodes.Status200OK)]
        [ProducesResponseType(StatusCodes.Status401Unauthorized)]
        [AllowAnonymous]
        public async Task<ActionResult<ReadTokenDto>> Login([FromBody] LoginUserDto loginUserDto)
        {
            var user = await _userManager.FindByNameAsync(loginUserDto.Username)
                .ConfigureAwait(true);
            if (user != null && await _userManager.CheckPasswordAsync(user, loginUserDto.Password)
                .ConfigureAwait(true))
            {
                var userRoles = await _userManager.GetRolesAsync(user)
                    .ConfigureAwait(true);

                var authClaims = new List<Claim>
                {
                    new Claim(ClaimTypes.Name, user.UserName),
                    new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString())
                };

                authClaims.AddRange(userRoles.Select(r => new Claim(ClaimTypes.Role, r)));

                var signingKey = new SymmetricSecurityKey(
                    Encoding.UTF8.GetBytes(_configuration["JWT:SecretKey"]));

                var token = new JwtSecurityToken(
                    issuer: _configuration["JWT:ValidIssuer"],
                    audience: _configuration["JWT:ValidAudience"],
                    expires: DateTime.Now.AddMinutes(30),
                    claims: authClaims,
                    signingCredentials: new SigningCredentials(signingKey,
                        SecurityAlgorithms.HmacSha256)
                );

                return Ok(new ReadTokenDto
                {
                    Token = new JwtSecurityTokenHandler()
                        .WriteToken(token),
                    Expiration = token.ValidTo
                });
            }

            return Unauthorized();
        }

        [HttpGet("{id}", Name = "GetUserById")]
        [ProducesResponseType(StatusCodes.Status200OK)]
        [ProducesResponseType(StatusCodes.Status404NotFound)]
        public async Task<ActionResult<ReadUserDto>> GetUserById(string id)
        {
            var user = await _userManager.FindByIdAsync(id)
                .ConfigureAwait(true);

            if (user == null)
            {
                return NotFound($"Couldn't find user with {nameof(id)}");
            }

            return Ok(_mapper.Map<ReadUserDto>(user));
        }

        [HttpGet(Name = "GetUser")]
        [ProducesResponseType(StatusCodes.Status200OK)]
        [ProducesResponseType(StatusCodes.Status404NotFound)]
        public async Task<ActionResult<ReadUserDto>> GetUser()
        {
            var userIdentity = HttpContext.User.Identity;
            var user = await _userManager.FindByNameAsync(userIdentity.Name)
                .ConfigureAwait(true);

            if (user == null)
            {
                return NotFound("Couldn't find user.");
            }

            return Ok(_mapper.Map<ReadUserDto>(user));
        }

        [HttpDelete(Name = "DeleteUser")]
        [ProducesResponseType(StatusCodes.Status200OK)]
        [ProducesResponseType(StatusCodes.Status400BadRequest)]
        [ProducesResponseType(StatusCodes.Status401Unauthorized)]
        [ProducesResponseType(StatusCodes.Status404NotFound)]
        public async Task<ActionResult> DeleteUser()
        {
            var userIdentity = HttpContext.User.Identity;
            if (!userIdentity.IsAuthenticated)
            {
                return Unauthorized();
            }

            var user = await _userManager.FindByNameAsync(userIdentity.Name)
                .ConfigureAwait(true);

            if (user == null)
            {
                return NotFound("Couldn't find user");
            }

            var result = await _userManager.DeleteAsync(user)
                .ConfigureAwait(true);
            if (!result.Succeeded)
            {
                return BadRequest();
            }

            _logger.LogInformation($"Successfully deleted user: {user.Id}");

            return Ok();
        }
    }
}