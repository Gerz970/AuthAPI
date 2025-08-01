using System.ComponentModel.DataAnnotations;

namespace AuthAPI.Dtos
{
    /// <summary>
    /// DTO para las credenciales de inicio de sesión de un usuario.
    /// </summary>
    public class LoginDto
    {
        /// <summary>
        /// Email del usuario. Es obligatorio y debe ser un email válido.
        /// </summary>
        [Required]
        public string Email { get; set; } = string.Empty;

        /// <summary>
        /// Contraseña del usuario. Es obligatoria.
        /// </summary>
        [Required]
        public string Password { get; set; } = string.Empty;
    }
}
