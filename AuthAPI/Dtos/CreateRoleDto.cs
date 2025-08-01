using System.ComponentModel.DataAnnotations;

namespace AuthAPI.Dtos;

/// <summary>
/// DTO para crear un nuevo rol en el sistema.
/// </summary>
public class CreateRoleDto
{
    /// <summary>
    /// Nombre del rol a crear. Es obligatorio y debe ser único en el sistema.
    /// Ejemplos: "Admin", "User", "Manager", "Editor"
    /// </summary>
    [Required(ErrorMessage = "Role name is required")]
    public string RoleName { get; set; } = null!;
}