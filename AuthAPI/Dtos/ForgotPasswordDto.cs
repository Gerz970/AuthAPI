namespace AuthAPI.Dtos
{
    /// <summary>
    /// DTO para la solicitud de recuperación de contraseña.
    /// </summary>
    public class ForgotPasswordDto
    {
        /// <summary>
        /// Email del usuario que solicita la recuperación de contraseña.
        /// </summary>
        public string Email { get; set; } = string.Empty;
    }
} 