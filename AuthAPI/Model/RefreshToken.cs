using System.ComponentModel.DataAnnotations;

namespace AuthAPI.Model
{
    /// <summary>
    /// Modelo para almacenar refresh tokens de usuarios.
    /// </summary>
    public class RefreshToken
    {
        /// <summary>
        /// ID único del refresh token.
        /// </summary>
        [Key]
        public string Token { get; set; } = string.Empty;

        /// <summary>
        /// ID del usuario propietario del token.
        /// </summary>
        public string UserId { get; set; } = string.Empty;

        /// <summary>
        /// Fecha de expiración del token.
        /// </summary>
        public DateTime ExpiryDate { get; set; }

        /// <summary>
        /// Indica si el token ha sido revocado.
        /// </summary>
        public bool IsRevoked { get; set; }

        /// <summary>
        /// Fecha de creación del token.
        /// </summary>
        public DateTime CreatedDate { get; set; } = DateTime.UtcNow;

        /// <summary>
        /// Navegación al usuario propietario.
        /// </summary>
        public virtual AppUser User { get; set; } = null!;
    }
} 