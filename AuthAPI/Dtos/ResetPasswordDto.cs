namespace AuthAPI.Dtos
{
    /// <summary>
    /// DTO para resetear la contraseña del usuario.
    /// </summary>
    public class ResetPasswordDto
    {
        /// <summary>
        /// Email del usuario.
        /// </summary>
        public string Email { get; set; } = string.Empty;

        /// <summary>
        /// Token de reset de contraseña.
        /// </summary>
        public string Token { get; set; } = string.Empty;

        /// <summary>
        /// Nueva contraseña.
        /// </summary>
        public string NewPassword { get; set; } = string.Empty;

        /// <summary>
        /// Confirmación de la nueva contraseña.
        /// </summary>
        public string ConfirmPassword { get; set; } = string.Empty;
    }
} 