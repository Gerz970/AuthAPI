namespace AuthAPI.Dtos
{
    /// <summary>
    /// DTO para respuestas de autenticación.
    /// </summary>
    public class AuthRespondeDto
    {
        /// <summary>
        /// Token JWT de acceso.
        /// </summary>
        public string? Token { get; set; } = string.Empty;

        /// <summary>
        /// Token de refresh para renovar el access token.
        /// </summary>
        public string? RefreshToken { get; set; } = string.Empty;

        /// <summary>
        /// Indica si la operación fue exitosa.
        /// </summary>
        public bool IsSuccess { get; set; }

        /// <summary>
        /// Mensaje de respuesta.
        /// </summary>
        public string? Message { get; set; }
    }
}
