namespace AuthAPI.Dtos;

/// <summary>
/// DTO para asignar un rol a un usuario específico.
/// </summary>
public class AssignRoleDto
{
    /// <summary>
    /// Identificador único del usuario al cual se le asignará el rol.
    /// </summary>
    public string UserId { get; set; } = null!;
    
    /// <summary>
    /// Identificador único del rol que se asignará al usuario.
    /// </summary>
    public string RoleId { get; set; } = null!;
}
