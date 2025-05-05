using JWTAuthenticationManager.Interfaces;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.Extensions.DependencyInjection;

namespace JWTAuthenticationManager.Extensions
{
    public static class JwtConfigurationExtensions
    {
        /// <summary>
        /// Adds and configures JWT authentication and authorization services for the application.
        /// </summary>
        /// <param name="services">The <see cref="IServiceCollection"/> to which the authentication services will be added.</param>
        /// <param name="options">The options for configuring JWT authentication.</param>
        /// <param name="settings">The settings for JWT authentication, including token validation parameters, and bearer options.</param>
        /// <exception cref="ArgumentNullException">Thrown if <paramref name="options"/> or <paramref name="settings"/> is null.</exception>
        public static void AddJwtAuthentication(this IServiceCollection services, JwtBearerOptions options, JwtSettings settings)
        {
            ArgumentNullException.ThrowIfNull(options);
            ArgumentNullException.ThrowIfNull(settings);

            services.AddSingleton(options.TokenValidationParameters);
            services.AddSingleton<IJwtAuthenticationManager, JwtAuthenticationManager>(sp => new JwtAuthenticationManager(settings));
            services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme).AddJwtBearer(o => o = options);
            services.AddAuthorization();
        }
    }
}
