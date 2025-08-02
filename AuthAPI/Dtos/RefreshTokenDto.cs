namespace AuthAPI.Dtos
{
    /// <summary>
    /// DTO para solicitar un nuevo access token usando refresh token.
    /// </summary>
    public class RefreshTokenDto
    {
        /// <summary>
        /// Token de refresh válido.
        /// </summary>
        public string RefreshToken { get; set; } = string.Empty;
    }
} 