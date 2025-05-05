using JWTAuthenticationManager.Interfaces;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;

namespace JWTAuthenticationManager
{
    /// <summary>
    /// Default implementation of <see cref="IJwtAuthenticationManager"/> that uses symmetric key signing
    /// to generate JWT tokens with configurable settings.
    /// </summary>
    public class JwtAuthenticationManager : IJwtAuthenticationManager
    {
        private readonly JwtSettings _settings;

        /// <summary>
        /// Initializes a new instance of the <see cref="JwtAuthenticationManager"/> class.
        /// </summary>
        /// <param name="settings">The JWT settings used to generate and validate tokens.</param>
        /// <exception cref="ArgumentNullException">Thrown when <paramref name="settings"/> is null.</exception>
        public JwtAuthenticationManager(JwtSettings settings)
        {
            _settings = settings ?? throw new ArgumentNullException(nameof(settings));
        }

        /// <inheritdoc />
        public string GenerateToken(List<Claim> claims)
        {
            if (_settings == null)
                throw new Exception("JWT settings are not configured.");

            if (claims == null || claims.Count == 0)
                throw new Exception("Claims are not provided.");
            
            var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_settings.SecretKey));
            var credentials = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);

            var token = new JwtSecurityToken(
                issuer: _settings.Issuer,
                audience: _settings.Audience,
                claims: claims,
                expires: DateTime.UtcNow.AddMinutes(_settings.ExpirationInMinutes),
                signingCredentials: credentials
            );
            
            return new JwtSecurityTokenHandler().WriteToken(token);
        }
    }
}
