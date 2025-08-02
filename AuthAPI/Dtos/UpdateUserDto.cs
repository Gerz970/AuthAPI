using System.ComponentModel.DataAnnotations;

namespace AuthAPI.Dtos
{
    /// <summary>
    /// DTO para actualizar información de un usuario existente.
    /// </summary>
    public class UpdateUserDto
    {
        /// <summary>
        /// ID del usuario a actualizar.
        /// </summary>
        [Required(ErrorMessage = "User ID is required")]
        public string Id { get; set; } = string.Empty;

        /// <summary>
        /// Email del usuario.
        /// </summary>
        [EmailAddress(ErrorMessage = "Invalid email format")]
        public string? Email { get; set; }

        /// <summary>
        /// Nombre completo del usuario.
        /// </summary>
        public string? FullName { get; set; }

        /// <summary>
        /// Número de teléfono del usuario.
        /// </summary>
        public string? PhoneNumber { get; set; }

        /// <summary>
        /// Lista de roles a asignar al usuario.
        /// </summary>
        public List<string>? Roles { get; set; }
    }
} 