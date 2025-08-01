using AuthAPI.Dtos;
using AuthAPI.Model;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;

namespace AuthAPI.Controllers;

/// <summary>
/// Controlador para gestionar roles de usuarios en el sistema de autenticación.
/// Proporciona endpoints para crear, listar, eliminar roles y asignar roles a usuarios.
/// </summary>
[ApiController]
[Route("api/[controller]")]
public class RolesController : ControllerBase
{
    private readonly RoleManager<IdentityRole> _roleManager;
    private readonly UserManager<AppUser> _userManager;

    /// <summary>
    /// Constructor del controlador de roles.
    /// </summary>
    /// <param name="roleManager">Servicio para gestionar roles de Identity</param>
    /// <param name="userManager">Servicio para gestionar usuarios de Identity</param>
    public RolesController(RoleManager<IdentityRole> roleManager, UserManager<AppUser> userManager)
    {
        _roleManager = roleManager;
        _userManager = userManager;
    }

    /// <summary>
    /// Crea un nuevo rol en el sistema.
    /// </summary>
    /// <param name="createRoleDto">Datos del rol a crear</param>
    /// <returns>
    /// - 200 OK: Rol creado exitosamente
    /// - 400 Bad Request: Si el nombre del rol está vacío o ya existe
    /// </returns>
    [HttpPost]
    public async Task<ActionResult> CreateRole([FromBody] CreateRoleDto createRoleDto)
    {
        // Validar que el nombre del rol no esté vacío
        if (String.IsNullOrEmpty(createRoleDto.RoleName))
        {
            return BadRequest("Role name is required");
        }

        // Verificar si el rol ya existe
        var roleExists = await _roleManager.RoleExistsAsync(createRoleDto.RoleName);
        if (roleExists)
        {
            return BadRequest("Role already exists");
        }

        // Crear el nuevo rol
        var roleResult = await _roleManager.CreateAsync(new IdentityRole(createRoleDto.RoleName));

        if (roleResult.Succeeded)
        {
            return Ok("Role created successfully");
        }
        return BadRequest("Failed to create role");
    }

    /// <summary>
    /// Obtiene la lista de todos los roles con el número de usuarios en cada uno.
    /// </summary>
    /// <returns>
    /// - 200 OK: Lista de roles con información detallada
    /// </returns>
    [HttpGet]
    public async Task<ActionResult<IEnumerable<RoleResponseDto>>> GetRoles()
    {
        // Obtener todos los roles con el conteo de usuarios en cada uno
        var roles = await _roleManager.Roles.Select(role => new RoleResponseDto
        {
            Id = role.Id,
            Name = role.Name,
            TotalUsers = _userManager.GetUsersInRoleAsync(role.Name!).Result.Count
        }).ToListAsync();
        
        return Ok(roles);
    }

    /// <summary>
    /// Elimina un rol específico por su ID.
    /// </summary>
    /// <param name="id">ID del rol a eliminar</param>
    /// <returns>
    /// - 200 OK: Rol eliminado exitosamente
    /// - 404 Not Found: Si el rol no existe
    /// - 400 Bad Request: Si hay un error al eliminar el rol
    /// </returns>
    [HttpDelete("{id}")]
    public async Task<ActionResult> DeleteRole(string id)
    {
        // Buscar el rol por ID
        var role = await _roleManager.FindByIdAsync(id);
        if (role == null)
        {
            return NotFound("Role not found");
        }

        // Eliminar el rol
        var result = await _roleManager.DeleteAsync(role);

        if (result.Succeeded)
        {
            return Ok("Role deleted successfully");
        }
        return BadRequest("Failed to delete role");
    }

    /// <summary>
    /// Asigna un rol específico a un usuario.
    /// </summary>
    /// <param name="assignRoleDto">Datos con el ID del usuario y el ID del rol</param>
    /// <returns>
    /// - 200 OK: Rol asignado exitosamente
    /// - 404 Not Found: Si el usuario o rol no existe
    /// - 400 Bad Request: Si hay un error al asignar el rol
    /// </returns>
    [HttpPost("assign")]
    public async Task<ActionResult> AssignRole([FromBody] AssignRoleDto assignRoleDto)
    {
        // Buscar el usuario por ID
        var user = await _userManager.FindByIdAsync(assignRoleDto.UserId);
        if (user == null)
        {
            return NotFound("User not found");
        }

        // Buscar el rol por ID
        var role = await _roleManager.FindByIdAsync(assignRoleDto.RoleId);
        if (role == null)
        {
            return NotFound("Role not found");
        }

        // Asignar el rol al usuario
        var result = await _userManager.AddToRoleAsync(user, role.Name!);

        if (result.Succeeded)
        {
            return Ok("Role assigned successfully");
        }
        
        return BadRequest(result.Errors);
    }
}