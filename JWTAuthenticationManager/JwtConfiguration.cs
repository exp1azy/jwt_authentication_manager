using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.IdentityModel.Tokens;

namespace JWTAuthenticationManager
{
    /// <summary>
    /// Represents a composite configuration used to set up JWT authentication in an ASP.NET Core application.
    /// </summary>
    public class JwtConfiguration
    {
        /// <summary>
        /// Gets or sets the core JWT settings such as secret key, issuer, audience, and expiration parameters.
        /// </summary>
        /// <remarks>
        /// These settings are used for signing and creating JWT tokens.
        /// </remarks>
        public JwtSettings JwtSettings { get; set; }

        /// <summary>
        /// Gets or sets the token validation parameters that are used by the JWT middleware
        /// to validate incoming tokens.
        /// </summary>
        /// <remarks>
        /// Includes settings such as signing key, clock skew, issuer and audience validation.
        /// This is required for configuring <see cref="JwtBearerOptions.TokenValidationParameters"/>.
        /// </remarks>
        public TokenValidationParameters TokenValidationParameters { get; set; }

        /// <summary>
        /// Gets or sets the bearer options used to configure the behavior of the JWT bearer authentication handler.
        /// </summary>
        /// <remarks>
        /// Use this to customize token validation events, error handling, and HTTPS metadata requirements.
        /// </remarks>
        public JwtBearerOptions JwtBearerOptions { get; set; }
    }
}
