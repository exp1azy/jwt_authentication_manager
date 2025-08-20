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

            services.AddSingleton<IJwtAuthenticationManager, JwtAuthenticationManager>(_ => new JwtAuthenticationManager(settings));
            services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme).AddJwtBearer(o =>
            {
                o.Audience = options.Audience;
                o.Authority = options.Authority;
                o.AutomaticRefreshInterval = options.AutomaticRefreshInterval;
                o.Backchannel = options.Backchannel;
                o.BackchannelHttpHandler = options.BackchannelHttpHandler;
                o.BackchannelTimeout = options.BackchannelTimeout;
                o.Challenge = options.Challenge;
                o.ClaimsIssuer = options.ClaimsIssuer;
                o.Configuration = options.Configuration;
                o.ConfigurationManager = options.ConfigurationManager;
                o.Events = options.Events;
                o.EventsType = options.EventsType;
                o.ForwardAuthenticate = options.ForwardAuthenticate;
                o.ForwardChallenge = options.ForwardChallenge;
                o.ForwardDefault = options.ForwardDefault;
                o.ForwardDefaultSelector = options.ForwardDefaultSelector;
                o.ForwardForbid = options.ForwardForbid;
                o.ForwardSignIn = options.ForwardSignIn;
                o.ForwardSignOut = options.ForwardSignOut;
                o.IncludeErrorDetails = options.IncludeErrorDetails;
                o.MapInboundClaims = options.MapInboundClaims;
                o.MetadataAddress = options.MetadataAddress;
                o.RefreshInterval = options.RefreshInterval;
                o.RefreshOnIssuerKeyNotFound = options.RefreshOnIssuerKeyNotFound;
                o.RequireHttpsMetadata = options.RequireHttpsMetadata;
                o.SaveToken = options.SaveToken;
                o.SecurityTokenValidators.Clear();
                foreach (var validator in options.SecurityTokenValidators)
                    o.SecurityTokenValidators.Add(validator);
                o.TokenValidationParameters = options.TokenValidationParameters;
            });
            services.AddAuthorization();
        }
    }
}
