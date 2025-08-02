using AuthAPI.Model;
using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;

namespace AuthAPI.Data
{
    /// <summary>
    /// Contexto de base de datos para la aplicación de autenticación.
    /// Extiende IdentityDbContext para manejar usuarios y roles de ASP.NET Core Identity.
    /// </summary>
    public class AppDbContext : IdentityDbContext<AppUser>
    {
        /// <summary>
        /// Constructor principal del contexto de base de datos.
        /// </summary>
        /// <param name="options">Opciones de configuración del contexto</param>
        public AppDbContext(DbContextOptions<AppDbContext> options) : base(options)
        {
        }

        /// <summary>
        /// Constructor sin parámetros para Entity Framework.
        /// </summary>
        protected AppDbContext()
        {
        }

        /// <summary>
        /// DbSet para los refresh tokens.
        /// </summary>
        public DbSet<RefreshToken> RefreshTokens { get; set; }

        /// <summary>
        /// Configuración del modelo de datos.
        /// </summary>
        /// <param name="modelBuilder">Constructor del modelo</param>
        protected override void OnModelCreating(ModelBuilder modelBuilder)
        {
            base.OnModelCreating(modelBuilder);

            // Configurar la relación entre RefreshToken y AppUser
            modelBuilder.Entity<RefreshToken>()
                .HasOne(rt => rt.User)
                .WithMany()
                .HasForeignKey(rt => rt.UserId)
                .OnDelete(DeleteBehavior.Cascade);
        }
    }
}
