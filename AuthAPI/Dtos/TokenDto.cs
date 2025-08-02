namespace AuthAPI.Dtos
{
    /// <summary>
    /// DTO para manejar tokens de acceso y refresh.
    /// </summary>
    public class TokenDto
    {
        /// <summary>
        /// Token de acceso JWT.
        /// </summary>
        public string AccessToken { get; set; } = string.Empty;

        /// <summary>
        /// Token de refresh para renovar el access token.
        /// </summary>
        public string RefreshToken { get; set; } = string.Empty;

        /// <summary>
        /// Fecha de expiración del access token.
        /// </summary>
        public DateTime ExpiresAt { get; set; }
    }
} 