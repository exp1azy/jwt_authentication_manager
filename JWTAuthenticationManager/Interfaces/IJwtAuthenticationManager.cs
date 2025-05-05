using System.Security.Claims;

namespace JWTAuthenticationManager.Interfaces
{
    /// <summary>
    /// Defines the contract for generating JWT tokens used in authentication and authorization.
    /// </summary>
    public interface IJwtAuthenticationManager
    {
        /// <summary>
        /// Generates a JWT string based on the provided claims.
        /// </summary>
        /// <param name="claims">A list of <see cref="Claim"/> instances that will be embedded in the token payload.</param>
        /// <returns>
        /// A signed JWT as a <see cref="string"/> containing the specified claims, ready to be returned to the client.
        /// </returns>
        public string GenerateToken(List<Claim> claims);

        /// <summary>
        /// Calculates the remaining lifetime, in seconds, of the specified JWT token.
        /// </summary>
        /// <param name="token">The JWT token string to analyze.</param>
        /// <returns>
        /// A <see cref="double"/> value representing the number of seconds remaining until the token expires.
        /// </returns>
        public double GetRemainingLifeTime(string token);
    }
}
