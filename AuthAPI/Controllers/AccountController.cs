using AuthAPI.Dtos;
using AuthAPI.Model;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;

namespace AuthAPI.Controllers
{
    /// <summary>
    /// Controlador para gestionar la autenticación y autorización de usuarios.
    /// Proporciona endpoints para registro, login y obtención de detalles de usuario.
    /// </summary>
    [Authorize(Roles = "Admin")]
    [ApiController]
    [Route("api/[controller]")]
    public class AccountController : ControllerBase
    {
        private readonly UserManager<AppUser> _userManager;
        private readonly RoleManager<IdentityRole> _roleManager;
        private readonly IConfiguration _configuration;

        /// <summary>
        /// Constructor del controlador de cuentas.
        /// </summary>
        /// <param name="userManager">Servicio para gestionar usuarios de Identity</param>
        /// <param name="roleManager">Servicio para gestionar roles de Identity</param>
        /// <param name="configuration">Configuración de la aplicación</param>
        public AccountController(UserManager<AppUser> userManager, RoleManager<IdentityRole> roleManager, IConfiguration configuration)
        {
            _userManager = userManager;
            _roleManager = roleManager;
            _configuration = configuration;
        }

        /// <summary>
        /// Registra un nuevo usuario en el sistema.
        /// </summary>
        /// <param name="registerDto">Datos del usuario a registrar</param>
        /// <returns>
        /// - 200 OK: Usuario registrado exitosamente
        /// - 400 Bad Request: Si los datos son inválidos o hay errores en el registro
        /// </returns>
        [AllowAnonymous]
        [HttpPost("register")]
        public async Task<ActionResult<string>> Register(RegisterDto registerDto)
        {
            // Validar el modelo de datos
            if (!ModelState.IsValid)
            {
                return BadRequest(ModelState);
            }

            // Crear el nuevo usuario
            var user = new AppUser
            {
                Email = registerDto.Email,
                FullName = registerDto.FullName,
                UserName = registerDto.Email
            };

            // Intentar crear el usuario
            var result = await _userManager.CreateAsync(user, registerDto.Password);

            if (!result.Succeeded)
            {
                return BadRequest(result.Errors);
            }

            // Asignar roles al usuario
            if (registerDto.Roles is null)
            {
                // Si no se especifican roles, asignar el rol "User" por defecto
                await _userManager.AddToRoleAsync(user, "User");
            }
            else
            {
                // Asignar los roles especificados
                foreach (var role in registerDto.Roles)
                {
                    await _userManager.AddToRoleAsync(user, role);
                }
            }

            return Ok(new AuthRespondeDto
            {
                IsSuccess = true,
                Message = "Account Created Successfully!!!"
            });
        }

        /// <summary>
        /// Autentica un usuario y genera un token JWT.
        /// </summary>
        /// <param name="loginDto">Credenciales de login</param>
        /// <returns>
        /// - 200 OK: Login exitoso con token JWT
        /// - 401 Unauthorized: Si las credenciales son inválidas
        /// - 400 Bad Request: Si el modelo es inválido
        /// </returns>
        [AllowAnonymous]
        [HttpPost("login")]
        public async Task<ActionResult<AuthRespondeDto>> Login(LoginDto loginDto)
        {
            // Validar el modelo de datos
            if (!ModelState.IsValid)
            {
                return BadRequest(ModelState);
            }

            // Buscar el usuario por email
            var user = await _userManager.FindByEmailAsync(loginDto.Email);

            if (user == null)
            {
                return Unauthorized(new AuthRespondeDto
                {
                    IsSuccess = false,
                    Message = "User not found with this email"
                });
            }

            // Verificar la contraseña
            var result = await _userManager.CheckPasswordAsync(user, loginDto.Password);

            if (!result)
            {
                return Unauthorized(new AuthRespondeDto
                {
                    IsSuccess = false,
                    Message = "Invalid Password"
                });
            }

            // Generar token JWT
            var token = GenerateToken(user);

            return Ok(new AuthRespondeDto
            {
                Token = token,
                IsSuccess = true,
                Message = "Login Success"
            });
        }

        /// <summary>
        /// Genera un token JWT para el usuario especificado.
        /// </summary>
        /// <param name="user">Usuario para el cual generar el token</param>
        /// <returns>Token JWT como string</returns>
        private string GenerateToken(AppUser user)
        {
            var tokenHandler = new JwtSecurityTokenHandler();

            // Obtener la clave secreta desde la configuración
            var key = Encoding.ASCII.GetBytes(_configuration.GetSection("JWTSetting").GetSection("securityKey").Value!);

            // Obtener los roles del usuario
            var roles = _userManager.GetRolesAsync(user).Result;

            // Crear las claims del token
            List<Claim> claims = [
                new (JwtRegisteredClaimNames.Email, user.Email??""),
                new (JwtRegisteredClaimNames.Name, user.FullName??""),
                new (JwtRegisteredClaimNames.NameId, user.Id??""),
                new (JwtRegisteredClaimNames.Aud, _configuration.GetSection("JWTSetting").GetSection("ValidAudience").Value!),
                new (JwtRegisteredClaimNames.Iss, _configuration.GetSection("JWTSetting").GetSection("ValidIssuer").Value!)
            ];

            // Agregar los roles como claims
            foreach (var role in roles)
            {
                claims.Add(new Claim(ClaimTypes.Role, role));
            }

            // Configurar el descriptor del token
            var tokenDescriptor = new SecurityTokenDescriptor
            {
                Subject = new ClaimsIdentity(claims),
                Expires = DateTime.UtcNow.AddDays(1),
                SigningCredentials = new SigningCredentials(
                    new SymmetricSecurityKey(key),
                    SecurityAlgorithms.HmacSha256
                )
            };

            // Crear y escribir el token
            var token = tokenHandler.CreateToken(tokenDescriptor);
            return tokenHandler.WriteToken(token);
        }

        /// <summary>
        /// Obtiene los detalles del usuario autenticado actualmente.
        /// </summary>
        /// <returns>
        /// - 200 OK: Detalles del usuario
        /// - 404 Not Found: Si el usuario no existe
        /// </returns>
        [Authorize]
        [HttpGet("detail")]
        public async Task<ActionResult<UserDetailDto>> GetUserDetail()
        {
            // Obtener el ID del usuario desde el token JWT
            var currentUserId = User.FindFirstValue(ClaimTypes.NameIdentifier);
            var user = await _userManager.FindByIdAsync(currentUserId!);

            if (user == null)
            {
                return NotFound(new AuthRespondeDto
                {
                    IsSuccess = false,
                    Message = "User not found"
                });
            }

            // Obtener los roles del usuario
            var userRoles = await _userManager.GetRolesAsync(user);

            return Ok(new UserDetailDto
            {
                Id = user.Id,
                Email = user.Email,
                FullName = user.FullName,
                Roles = [.. userRoles],
                PhoneNumber = user.PhoneNumber,
                PhoneNumberConfirmed = user.PhoneNumberConfirmed,
                AccessFailedCount = user.AccessFailedCount
            });
        }
    }
}