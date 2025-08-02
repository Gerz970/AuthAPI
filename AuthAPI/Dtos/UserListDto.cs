namespace AuthAPI.Dtos
{
    /// <summary>
    /// DTO para mostrar la lista de usuarios en el sistema.
    /// </summary>
    public class UserListDto
    {
        /// <summary>
        /// ID único del usuario.
        /// </summary>
        public string Id { get; set; } = string.Empty;

        /// <summary>
        /// Email del usuario.
        /// </summary>
        public string Email { get; set; } = string.Empty;

        /// <summary>
        /// Nombre completo del usuario.
        /// </summary>
        public string FullName { get; set; } = string.Empty;

        /// <summary>
        /// Lista de roles asignados al usuario.
        /// </summary>
        public List<string> Roles { get; set; } = new List<string>();

        /// <summary>
        /// Número de teléfono del usuario.
        /// </summary>
        public string? PhoneNumber { get; set; }

        /// <summary>
        /// Indica si el número de teléfono está confirmado.
        /// </summary>
        public bool PhoneNumberConfirmed { get; set; }

        /// <summary>
        /// Número de intentos fallidos de acceso.
        /// </summary>
        public int AccessFailedCount { get; set; }
    }
} 