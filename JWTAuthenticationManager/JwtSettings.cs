namespace JWTAuthenticationManager
{
    /// <summary>
    /// Represents configuration settings used for generating and validating JWT tokens.
    /// </summary>
    public class JwtSettings
    {
        /// <summary>
        /// Gets or sets the secret key used to sign JWT tokens.
        /// </summary>
        /// <remarks>
        /// This key must be kept secure and should be long enough to ensure cryptographic strength.
        /// Typically stored in a secure configuration store or environment variable.
        /// </remarks>
        public string SecretKey { get; set; } = null!;

        /// <summary>
        /// Gets or sets the issuer (iss) claim for the JWT token.
        /// </summary>
        /// <remarks>
        /// This value identifies the authority that issued the token.
        /// It's used during token validation to ensure the token came from a trusted source.
        /// </remarks>
        public string Issuer { get; set; } = null!;

        /// <summary>
        /// Gets or sets the audience (aud) claim for the JWT token.
        /// </summary>
        /// <remarks>
        /// This value identifies the intended recipient(s) of the token.
        /// It's used during validation to ensure the token is meant for the current application.
        /// </remarks>
        public string Audience { get; set; } = null!;

        /// <summary>
        /// Gets or sets the lifetime of the JWT token in minutes.
        /// </summary>
        /// <remarks>
        /// After this duration, the token will expire and must be refreshed or re-issued.
        /// </remarks>
        public int ExpirationInMinutes { get; set; }
    }

}
