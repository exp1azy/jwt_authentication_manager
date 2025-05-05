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
        /// <param name="configuration">An instance of <see cref="JwtConfiguration"/> that provides the JWT settings, 
        /// token validation parameters, and bearer options.</param>
        /// <exception cref="Exception">
        /// Thrown if the <paramref name="configuration"/> parameter is null.
        /// </exception>
        public static void AddJwtAuthentication(this IServiceCollection services, JwtConfiguration configuration)
        {
            ArgumentNullException.ThrowIfNull(configuration);

            services.AddSingleton(configuration.TokenValidationParameters);
            services.AddSingleton<IJwtAuthenticationManager, JwtAuthenticationManager>(sp => new JwtAuthenticationManager(configuration.JwtSettings));
            services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme).AddJwtBearer(options => { options = configuration.JwtBearerOptions; });
            services.AddAuthorization();
        }
    }
}
