using System.ComponentModel.DataAnnotations;

namespace AuthAPI.Dtos
{
    /// <summary>
    /// DTO para el registro de un nuevo usuario en el sistema.
    /// </summary>
    public class RegisterDto
    {
        /// <summary>
        /// Email del usuario. Es obligatorio y debe ser un email válido.
        /// Se usará también como nombre de usuario.
        /// </summary>
        [Required]
        [EmailAddress]
        public string Email{ get; set; } = string.Empty;

        /// <summary>
        /// Nombre completo del usuario. Es obligatorio.
        /// </summary>
        [Required]
        public string FullName { get; set; } = string.Empty;

        /// <summary>
        /// Contraseña del usuario. Es obligatoria.
        /// </summary>
        public string Password { get; set; } = string.Empty;

        /// <summary>
        /// Lista opcional de roles a asignar al usuario.
        /// Si no se especifica, se asignará el rol "User" por defecto.
        /// </summary>
        public List<string>? Roles { get; set; }
    }
}
