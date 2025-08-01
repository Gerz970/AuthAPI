using Microsoft.AspNetCore.Identity;

namespace AuthAPI.Model
{
    /// <summary>
    /// Modelo de usuario personalizado que extiende IdentityUser.
    /// Representa un usuario en el sistema de autenticación.
    /// </summary>
    public class AppUser: IdentityUser
    {
        /// <summary>
        /// Nombre completo del usuario.
        /// </summary>
        public string? FullName { get; set; }
    }
}
