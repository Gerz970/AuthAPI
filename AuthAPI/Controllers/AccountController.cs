using AuthAPI.Dtos;
using AuthAPI.Data;
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
using System.Net.Mail;
using System.Net;

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
        /// Autentica un usuario y genera un token JWT con refresh token.
        /// </summary>
        /// <param name="loginDto">Credenciales de login</param>
        /// <returns>
        /// - 200 OK: Login exitoso con token JWT y refresh token
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

            // Generar token JWT y refresh token
            var token = GenerateToken(user);
            var refreshToken = await GenerateRefreshToken(user);

            return Ok(new AuthRespondeDto
            {
                Token = token,
                RefreshToken = refreshToken,
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

        /// <summary>
        /// Obtiene la lista de todos los usuarios en el sistema (solo para administradores).
        /// </summary>
        /// <returns>
        /// - 200 OK: Lista de usuarios
        /// - 403 Forbidden: Si el usuario no es administrador
        /// </returns>
        [Authorize(Roles = "Admin")]
        [HttpGet("users")]
        public async Task<ActionResult<IEnumerable<UserListDto>>> GetAllUsers()
        {
            var users = await _userManager.Users.ToListAsync();
            var userList = new List<UserListDto>();

            foreach (var user in users)
            {
                var roles = await _userManager.GetRolesAsync(user);
                userList.Add(new UserListDto
                {
                    Id = user.Id,
                    Email = user.Email,
                    FullName = user.FullName,
                    Roles = [.. roles],
                    PhoneNumber = user.PhoneNumber,
                    PhoneNumberConfirmed = user.PhoneNumberConfirmed,
                    AccessFailedCount = user.AccessFailedCount
                });
            }

            return Ok(userList);
        }

        /// <summary>
        /// Actualiza la información de un usuario específico.
        /// </summary>
        /// <param name="updateUserDto">Datos del usuario a actualizar</param>
        /// <returns>
        /// - 200 OK: Usuario actualizado exitosamente
        /// - 404 Not Found: Si el usuario no existe
        /// - 400 Bad Request: Si los datos son inválidos o hay errores
        /// </returns>
        [Authorize(Roles = "Admin")]
        [HttpPut("users")]
        public async Task<ActionResult<AuthRespondeDto>> UpdateUser([FromBody] UpdateUserDto updateUserDto)
        {
            // Validar el modelo de datos
            if (!ModelState.IsValid)
            {
                return BadRequest(ModelState);
            }

            // Buscar el usuario por ID
            var user = await _userManager.FindByIdAsync(updateUserDto.Id);
            if (user == null)
            {
                return NotFound(new AuthRespondeDto
                {
                    IsSuccess = false,
                    Message = "User not found"
                });
            }

            // Actualizar propiedades del usuario
            if (!string.IsNullOrEmpty(updateUserDto.Email))
            {
                user.Email = updateUserDto.Email;
                user.UserName = updateUserDto.Email;
            }

            if (!string.IsNullOrEmpty(updateUserDto.FullName))
            {
                user.FullName = updateUserDto.FullName;
            }

            if (updateUserDto.PhoneNumber != null)
            {
                user.PhoneNumber = updateUserDto.PhoneNumber;
            }

            // Actualizar el usuario
            var result = await _userManager.UpdateAsync(user);
            if (!result.Succeeded)
            {
                return BadRequest(new AuthRespondeDto
                {
                    IsSuccess = false,
                    Message = "Failed to update user"
                });
            }

            // Actualizar roles si se especifican
            if (updateUserDto.Roles != null)
            {
                // Obtener roles actuales
                var currentRoles = await _userManager.GetRolesAsync(user);
                
                // Remover roles actuales
                if (currentRoles.Any())
                {
                    await _userManager.RemoveFromRolesAsync(user, currentRoles);
                }
                
                // Agregar nuevos roles
                foreach (var role in updateUserDto.Roles)
                {
                    if (await _roleManager.RoleExistsAsync(role))
                    {
                        await _userManager.AddToRoleAsync(user, role);
                    }
                }
            }

            return Ok(new AuthRespondeDto
            {
                IsSuccess = true,
                Message = "User updated successfully"
            });
        }

        /// <summary>
        /// Elimina un usuario específico del sistema.
        /// </summary>
        /// <param name="id">ID del usuario a eliminar</param>
        /// <returns>
        /// - 200 OK: Usuario eliminado exitosamente
        /// - 404 Not Found: Si el usuario no existe
        /// - 400 Bad Request: Si hay un error al eliminar el usuario
        /// </returns>
        [Authorize(Roles = "Admin")]
        [HttpDelete("users/{id}")]
        public async Task<ActionResult<AuthRespondeDto>> DeleteUser(string id)
        {
            // Buscar el usuario por ID
            var user = await _userManager.FindByIdAsync(id);
            if (user == null)
            {
                return NotFound(new AuthRespondeDto
                {
                    IsSuccess = false,
                    Message = "User not found"
                });
            }

            // Verificar que no se elimine a sí mismo
            var currentUserId = User.FindFirstValue(ClaimTypes.NameIdentifier);
            if (user.Id == currentUserId)
            {
                return BadRequest(new AuthRespondeDto
                {
                    IsSuccess = false,
                    Message = "Cannot delete your own account"
                });
            }

            // Eliminar el usuario
            var result = await _userManager.DeleteAsync(user);
            if (!result.Succeeded)
            {
                return BadRequest(new AuthRespondeDto
                {
                    IsSuccess = false,
                    Message = "Failed to delete user"
                });
            }

            return Ok(new AuthRespondeDto
            {
                IsSuccess = true,
                Message = "User deleted successfully"
            });
        }

        /// <summary>
        /// Envía un email de recuperación de contraseña al usuario.
        /// </summary>
        /// <param name="forgotPasswordDto">Datos del email para recuperación</param>
        /// <returns>
        /// - 200 OK: Email enviado exitosamente
        /// - 404 Not Found: Si el usuario no existe
        /// - 400 Bad Request: Si hay un error al enviar el email
        /// </returns>
        [AllowAnonymous]
        [HttpPost("forgot-password")]
        public async Task<ActionResult<AuthRespondeDto>> ForgotPassword(ForgotPasswordDto forgotPasswordDto)
        {
            var user = await _userManager.FindByEmailAsync(forgotPasswordDto.Email);
            if (user == null)
            {
                return NotFound(new AuthRespondeDto
                {
                    IsSuccess = false,
                    Message = "User not found with this email"
                });
            }

            var token = await _userManager.GeneratePasswordResetTokenAsync(user);
            var resetLink = $"{Request.Scheme}://{Request.Host}/api/account/reset-password?email={user.Email}&token={token}";

            // Enviar email (configurar SMTP en appsettings.json)
            try
            {
                await SendPasswordResetEmail(user.Email, resetLink);
                return Ok(new AuthRespondeDto
                {
                    IsSuccess = true,
                    Message = "Password reset link has been sent to your email"
                });
            }
            catch (Exception ex)
            {
                return BadRequest(new AuthRespondeDto
                {
                    IsSuccess = false,
                    Message = $"Failed to send email: {ex.Message}"
                });
            }
        }

        /// <summary>
        /// Resetea la contraseña del usuario usando el token de recuperación.
        /// </summary>
        /// <param name="resetPasswordDto">Datos para resetear la contraseña</param>
        /// <returns>
        /// - 200 OK: Contraseña reseteada exitosamente
        /// - 400 Bad Request: Si los datos son inválidos o hay errores
        /// </returns>
        [AllowAnonymous]
        [HttpPost("reset-password")]
        public async Task<ActionResult<AuthRespondeDto>> ResetPassword(ResetPasswordDto resetPasswordDto)
        {
            if (resetPasswordDto.NewPassword != resetPasswordDto.ConfirmPassword)
            {
                return BadRequest(new AuthRespondeDto
                {
                    IsSuccess = false,
                    Message = "Passwords do not match"
                });
            }

            var user = await _userManager.FindByEmailAsync(resetPasswordDto.Email);
            if (user == null)
            {
                return NotFound(new AuthRespondeDto
                {
                    IsSuccess = false,
                    Message = "User not found"
                });
            }

            var result = await _userManager.ResetPasswordAsync(user, resetPasswordDto.Token, resetPasswordDto.NewPassword);

            if (result.Succeeded)
            {
                return Ok(new AuthRespondeDto
                {
                    IsSuccess = true,
                    Message = "Password has been reset successfully"
                });
            }

            return BadRequest(new AuthRespondeDto
            {
                IsSuccess = false,
                Message = "Failed to reset password"
            });
        }

        /// <summary>
        /// Cambia la contraseña del usuario autenticado.
        /// </summary>
        /// <param name="changePasswordDto">Datos para cambiar la contraseña</param>
        /// <returns>
        /// - 200 OK: Contraseña cambiada exitosamente
        /// - 400 Bad Request: Si los datos son inválidos o hay errores
        /// </returns>
        [Authorize]
        [HttpPost("change-password")]
        public async Task<ActionResult<AuthRespondeDto>> ChangePassword(ChangePasswordDto changePasswordDto)
        {
            if (changePasswordDto.NewPassword != changePasswordDto.ConfirmPassword)
            {
                return BadRequest(new AuthRespondeDto
                {
                    IsSuccess = false,
                    Message = "New password and confirm password do not match"
                });
            }

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

            var result = await _userManager.ChangePasswordAsync(user, changePasswordDto.CurrentPassword, changePasswordDto.NewPassword);

            if (result.Succeeded)
            {
                return Ok(new AuthRespondeDto
                {
                    IsSuccess = true,
                    Message = "Password changed successfully"
                });
            }

            return BadRequest(new AuthRespondeDto
            {
                IsSuccess = false,
                Message = "Failed to change password"
            });
        }

        /// <summary>
        /// Genera un nuevo access token usando un refresh token válido.
        /// </summary>
        /// <param name="refreshTokenDto">Datos del refresh token</param>
        /// <returns>
        /// - 200 OK: Nuevo access token generado
        /// - 401 Unauthorized: Si el refresh token es inválido
        /// </returns>
        [AllowAnonymous]
        [HttpPost("refresh-token")]
        public async Task<ActionResult<AuthRespondeDto>> RefreshToken(RefreshTokenDto refreshTokenDto)
        {
            var refreshToken = await GetRefreshToken(refreshTokenDto.RefreshToken);
            
            if (refreshToken == null || refreshToken.IsRevoked || refreshToken.ExpiryDate < DateTime.UtcNow)
            {
                return Unauthorized(new AuthRespondeDto
                {
                    IsSuccess = false,
                    Message = "Invalid or expired refresh token"
                });
            }

            var user = await _userManager.FindByIdAsync(refreshToken.UserId);
            if (user == null)
            {
                return Unauthorized(new AuthRespondeDto
                {
                    IsSuccess = false,
                    Message = "User not found"
                });
            }

            // Generar nuevo access token
            var newAccessToken = GenerateToken(user);
            
            // Generar nuevo refresh token
            var newRefreshToken = await GenerateRefreshToken(user);
            
            // Revocar el refresh token anterior
            refreshToken.IsRevoked = true;
            await UpdateRefreshToken(refreshToken);

            return Ok(new AuthRespondeDto
            {
                Token = newAccessToken,
                RefreshToken = newRefreshToken,
                IsSuccess = true,
                Message = "Token refreshed successfully"
            });
        }

        /// <summary>
        /// Revoca el refresh token del usuario autenticado.
        /// </summary>
        /// <returns>
        /// - 200 OK: Token revocado exitosamente
        /// - 400 Bad Request: Si hay un error al revocar el token
        /// </returns>
        [Authorize]
        [HttpPost("revoke-token")]
        public async Task<ActionResult<AuthRespondeDto>> RevokeToken()
        {
            var currentUserId = User.FindFirstValue(ClaimTypes.NameIdentifier);
            var refreshTokens = await GetRefreshTokensByUserId(currentUserId!);
            
            foreach (var token in refreshTokens)
            {
                token.IsRevoked = true;
                await UpdateRefreshToken(token);
            }

            return Ok(new AuthRespondeDto
            {
                IsSuccess = true,
                Message = "All refresh tokens have been revoked"
            });
        }

        /// <summary>
        /// Genera un refresh token para el usuario especificado.
        /// </summary>
        /// <param name="user">Usuario para el cual generar el token</param>
        /// <returns>Refresh token como string</returns>
        private async Task<string> GenerateRefreshToken(AppUser user)
        {
            var refreshToken = Guid.NewGuid().ToString();
            var expiryDate = DateTime.UtcNow.AddDays(7); // 7 días de validez

            var refreshTokenEntity = new RefreshToken
            {
                Token = refreshToken,
                UserId = user.Id,
                ExpiryDate = expiryDate,
                IsRevoked = false
            };

            // Guardar en la base de datos
            var dbContext = HttpContext.RequestServices.GetRequiredService<AppDbContext>();
            dbContext.RefreshTokens.Add(refreshTokenEntity);
            await dbContext.SaveChangesAsync();

            return refreshToken;
        }

        /// <summary>
        /// Obtiene un refresh token por su valor.
        /// </summary>
        /// <param name="token">Valor del refresh token</param>
        /// <returns>RefreshToken o null si no existe</returns>
        private async Task<RefreshToken?> GetRefreshToken(string token)
        {
            var dbContext = HttpContext.RequestServices.GetRequiredService<AppDbContext>();
            return await dbContext.RefreshTokens.FirstOrDefaultAsync(rt => rt.Token == token);
        }

        /// <summary>
        /// Obtiene todos los refresh tokens de un usuario.
        /// </summary>
        /// <param name="userId">ID del usuario</param>
        /// <returns>Lista de refresh tokens</returns>
        private async Task<List<RefreshToken>> GetRefreshTokensByUserId(string userId)
        {
            var dbContext = HttpContext.RequestServices.GetRequiredService<AppDbContext>();
            return await dbContext.RefreshTokens.Where(rt => rt.UserId == userId).ToListAsync();
        }

        /// <summary>
        /// Actualiza un refresh token en la base de datos.
        /// </summary>
        /// <param name="refreshToken">Token a actualizar</param>
        /// <returns>Task</returns>
        private async Task UpdateRefreshToken(RefreshToken refreshToken)
        {
            var dbContext = HttpContext.RequestServices.GetRequiredService<AppDbContext>();
            dbContext.RefreshTokens.Update(refreshToken);
            await dbContext.SaveChangesAsync();
        }

        /// <summary>
        /// Envía un email de recuperación de contraseña.
        /// </summary>
        /// <param name="email">Email del destinatario</param>
        /// <param name="resetLink">Enlace de recuperación</param>
        /// <returns>Task</returns>
        private async Task SendPasswordResetEmail(string email, string resetLink)
        {
            try
            {
                // Configurar SMTP desde appsettings.json
                var smtpSettings = _configuration.GetSection("SmtpSettings");
                var smtpServer = smtpSettings["SmtpServer"];
                var smtpPort = int.Parse(smtpSettings["SmtpPort"]);
                var smtpUsername = smtpSettings["SmtpUsername"];
                var smtpPassword = smtpSettings["SmtpPassword"];

                // Verificar si la configuración está completa
                if (string.IsNullOrEmpty(smtpServer) || string.IsNullOrEmpty(smtpUsername) || string.IsNullOrEmpty(smtpPassword))
                {
                    // Configuración incompleta - solo log para desarrollo
                    Console.WriteLine($"🔧 DESARROLLO: Email simulado para {email}");
                    Console.WriteLine($"🔧 DESARROLLO: Reset link: {resetLink}");
                    return;
                }

                using var client = new SmtpClient(smtpServer, smtpPort)
                {
                    EnableSsl = true,
                    Credentials = new NetworkCredential(smtpUsername, smtpPassword)
                };

                var mailMessage = new MailMessage
                {
                    From = new MailAddress(smtpUsername),
                    Subject = "Password Reset Request",
                    Body = $"Click the following link to reset your password: {resetLink}",
                    IsBodyHtml = true
                };
                mailMessage.To.Add(email);

                await client.SendMailAsync(mailMessage);
            }
            catch (Exception ex)
            {
                // En desarrollo, mostrar el error pero no fallar
                Console.WriteLine($"⚠️ Error enviando email: {ex.Message}");
                Console.WriteLine($"🔧 DESARROLLO: Reset link para {email}: {resetLink}");
            }
        }
    }
}