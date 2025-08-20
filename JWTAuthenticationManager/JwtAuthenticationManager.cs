using JWTAuthenticationManager.Extensions;
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
        private readonly JwtSecurityTokenHandler _tokenHandler;

        /// <summary>
        /// Initializes a new instance of the <see cref="JwtAuthenticationManager"/> class.
        /// </summary>
        /// <param name="settings">The JWT settings used to generate and validate tokens.</param>
        /// <exception cref="ArgumentNullException">Thrown when <paramref name="settings"/> is null.</exception>
        public JwtAuthenticationManager(JwtSettings settings)
        {
            _settings = settings ?? throw new ArgumentNullException(nameof(settings));
            _tokenHandler = new JwtSecurityTokenHandler();
        }

        /// <inheritdoc />
        public string GenerateToken(List<Claim> claims, SecurityAlgorithm securityAlgorithm = SecurityAlgorithm.HmacSha256)
        {
            if (_settings == null)
                throw new Exception("JWT settings are not configured.");

            if (claims == null || claims.Count == 0)
                throw new Exception("Claims are not provided.");

            if (string.IsNullOrEmpty(_settings.SecretKey))
                throw new Exception("Secret key is not provided.");
            
            var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_settings.SecretKey));
            var credentials = new SigningCredentials(key, securityAlgorithm.ToAlgorithmString());

            var now = DateTime.UtcNow;

            var token = new JwtSecurityToken(
                issuer: _settings.Issuer,
                audience: _settings.Audience,
                claims: claims,
                notBefore: _settings.NotBefore ?? now,
                expires: _settings.ExpirationInMinutes == null ? null : DateTime.UtcNow.AddMinutes(_settings.ExpirationInMinutes.Value),
                signingCredentials: credentials
            );
            
            return _tokenHandler.WriteToken(token);
        }

        /// <inheritdoc />
        public double GetRemainingLifeTime(string token)
        {
            if (string.IsNullOrEmpty(token))
                throw new Exception("Token is not provided.");

            if (token.StartsWith("Bearer ", StringComparison.OrdinalIgnoreCase))
                token = token["Bearer ".Length..].Trim();

            if (!_tokenHandler.CanReadToken(token))
                throw new SecurityTokenMalformedException("The token is not in a valid JWT format.");

            var jwtToken = _tokenHandler.ReadJwtToken(token);
            return jwtToken.ValidTo.Subtract(DateTime.UtcNow).TotalSeconds;
        }

        /// <inheritdoc />
        public JwtSecurityToken ReadToken(string token)
        {
            if (string.IsNullOrEmpty(token))
                throw new Exception("Token is not provided.");

            if (!_tokenHandler.CanReadToken(token))
                throw new SecurityTokenMalformedException("The token is not in a valid JWT format.");

            return _tokenHandler.ReadJwtToken(token);
        }
    }
}
