using Microsoft.IdentityModel.Tokens;

namespace JWTAuthenticationManager.Extensions
{
    internal static class SecurityAlgorithmExtensions
    {
        /// <summary>
        /// Maps a <see cref="SecurityAlgorithm"/> enum value to its corresponding algorithm URI or JWT-friendly string.
        /// </summary>
        internal static string ToAlgorithmString(this SecurityAlgorithm algorithm) => algorithm switch
        {
            SecurityAlgorithm.Aes128Encryption => SecurityAlgorithms.Aes128Encryption,
            SecurityAlgorithm.Aes192Encryption => SecurityAlgorithms.Aes192Encryption,
            SecurityAlgorithm.Aes256Encryption => SecurityAlgorithms.Aes256Encryption,
            SecurityAlgorithm.DesEncryption => SecurityAlgorithms.DesEncryption,
            SecurityAlgorithm.Aes128KeyWrap => SecurityAlgorithms.Aes128KeyWrap,
            SecurityAlgorithm.Aes192KeyWrap => SecurityAlgorithms.Aes192KeyWrap,
            SecurityAlgorithm.Aes256KeyWrap => SecurityAlgorithms.Aes256KeyWrap,
            SecurityAlgorithm.RsaV15KeyWrap => SecurityAlgorithms.RsaV15KeyWrap,
            SecurityAlgorithm.RsaOaepKeyWrap => SecurityAlgorithms.RsaOaepKeyWrap,
            SecurityAlgorithm.Ripemd160Digest => SecurityAlgorithms.Ripemd160Digest,
            SecurityAlgorithm.Sha256Digest => SecurityAlgorithms.Sha256Digest,
            SecurityAlgorithm.Sha384Digest => SecurityAlgorithms.Sha384Digest,
            SecurityAlgorithm.Sha512Digest => SecurityAlgorithms.Sha512Digest,
            SecurityAlgorithm.Sha256 => SecurityAlgorithms.Sha256,
            SecurityAlgorithm.Sha384 => SecurityAlgorithms.Sha384,
            SecurityAlgorithm.Sha512 => SecurityAlgorithms.Sha512,
            SecurityAlgorithm.EcdsaSha256Signature => SecurityAlgorithms.EcdsaSha256Signature,
            SecurityAlgorithm.EcdsaSha384Signature => SecurityAlgorithms.EcdsaSha384Signature,
            SecurityAlgorithm.EcdsaSha512Signature => SecurityAlgorithms.EcdsaSha512Signature,
            SecurityAlgorithm.HmacSha256Signature => SecurityAlgorithms.HmacSha256Signature,
            SecurityAlgorithm.HmacSha384Signature => SecurityAlgorithms.HmacSha384Signature,
            SecurityAlgorithm.HmacSha512Signature => SecurityAlgorithms.HmacSha512Signature,
            SecurityAlgorithm.RsaSha256Signature => SecurityAlgorithms.RsaSha256Signature,
            SecurityAlgorithm.RsaSha384Signature => SecurityAlgorithms.RsaSha384Signature,
            SecurityAlgorithm.RsaSha512Signature => SecurityAlgorithms.RsaSha512Signature,
            SecurityAlgorithm.RsaSsaPssSha256Signature => SecurityAlgorithms.RsaSsaPssSha256Signature,
            SecurityAlgorithm.RsaSsaPssSha384Signature => SecurityAlgorithms.RsaSsaPssSha384Signature,
            SecurityAlgorithm.RsaSsaPssSha512Signature => SecurityAlgorithms.RsaSsaPssSha512Signature,
            SecurityAlgorithm.EcdsaSha256 => SecurityAlgorithms.EcdsaSha256,
            SecurityAlgorithm.EcdsaSha384 => SecurityAlgorithms.EcdsaSha384,
            SecurityAlgorithm.EcdsaSha512 => SecurityAlgorithms.EcdsaSha512,
            SecurityAlgorithm.HmacSha256 => SecurityAlgorithms.HmacSha256,
            SecurityAlgorithm.HmacSha384 => SecurityAlgorithms.HmacSha384,
            SecurityAlgorithm.HmacSha512 => SecurityAlgorithms.HmacSha512,
            SecurityAlgorithm.None => SecurityAlgorithms.None,
            SecurityAlgorithm.RsaSha256 => SecurityAlgorithms.RsaSha256,
            SecurityAlgorithm.RsaSha384 => SecurityAlgorithms.RsaSha384,
            SecurityAlgorithm.RsaSha512 => SecurityAlgorithms.RsaSha512,
            SecurityAlgorithm.RsaSsaPssSha256 => SecurityAlgorithms.RsaSsaPssSha256,
            SecurityAlgorithm.RsaSsaPssSha384 => SecurityAlgorithms.RsaSsaPssSha384,
            SecurityAlgorithm.RsaSsaPssSha512 => SecurityAlgorithms.RsaSsaPssSha512,
            SecurityAlgorithm.Aes128CbcHmacSha256 => SecurityAlgorithms.Aes128CbcHmacSha256,
            SecurityAlgorithm.Aes192CbcHmacSha384 => SecurityAlgorithms.Aes192CbcHmacSha384,
            SecurityAlgorithm.Aes256CbcHmacSha512 => SecurityAlgorithms.Aes256CbcHmacSha512,
            SecurityAlgorithm.Aes128Gcm => SecurityAlgorithms.Aes128Gcm,
            SecurityAlgorithm.Aes192Gcm => SecurityAlgorithms.Aes192Gcm,
            SecurityAlgorithm.Aes256Gcm => SecurityAlgorithms.Aes256Gcm,
            SecurityAlgorithm.ExclusiveC14n => SecurityAlgorithms.ExclusiveC14n,
            SecurityAlgorithm.ExclusiveC14nWithComments => SecurityAlgorithms.ExclusiveC14nWithComments,
            SecurityAlgorithm.EnvelopedSignature => SecurityAlgorithms.EnvelopedSignature,
            SecurityAlgorithm.EcdhEsA128kw => SecurityAlgorithms.EcdhEsA128kw,
            SecurityAlgorithm.EcdhEsA192kw => SecurityAlgorithms.EcdhEsA192kw,
            SecurityAlgorithm.EcdhEsA256kw => SecurityAlgorithms.EcdhEsA256kw,
            SecurityAlgorithm.EcdhEs => SecurityAlgorithms.EcdhEs,

            _ => throw new NotSupportedException($"Unsupported algorithm: {algorithm}")
        };
    }
}
