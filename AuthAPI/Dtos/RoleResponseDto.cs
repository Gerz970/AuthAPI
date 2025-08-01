namespace AuthAPI.Dtos;

/// <summary>
/// DTO para la respuesta de información de roles.
/// Contiene los datos básicos de un rol y el número de usuarios que lo tienen asignado.
/// </summary>
public class RoleResponseDto
{
    /// <summary>
    /// Identificador único del rol.
    /// </summary>
    public string? Id { get; set; }
    
    /// <summary>
    /// Nombre del rol (ej: "Admin", "User", "Manager").
    /// </summary>
    public string? Name { get; set; }
    
    /// <summary>
    /// Número total de usuarios que tienen asignado este rol.
    /// </summary>
    public int TotalUsers { get; set; }
}
