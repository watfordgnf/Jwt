using System;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

using JsonWebToken.Internal;

using Xunit;

namespace JsonWebToken.Tests
{
    public class JwkTests
    {
#if NETCOREAPP3_1_OR_GREATER
        [Theory]
        [InlineData("SHA256")]
        [InlineData("SHA384")]
        [InlineData("SHA512")]
        public void FromRSACertificateTest(string hashAlgorithmName)
        {
            using var rsaKey = RSA.Create(2048);
            var csr = new CertificateRequest("cn=test", rsaKey, new HashAlgorithmName(hashAlgorithmName), RSASignaturePadding.Pkcs1);
            csr.CertificateExtensions.Add(
                new X509BasicConstraintsExtension(false, false, 0, false));
            csr.CertificateExtensions.Add(
                new X509KeyUsageExtension(X509KeyUsageFlags.DigitalSignature | X509KeyUsageFlags.NonRepudiation, false));
            csr.CertificateExtensions.Add(
                new X509EnhancedKeyUsageExtension(
                    new OidCollection
                    {
                        new Oid("1.3.6.1.5.5.7.3.8")
                    },
                    true));
            csr.CertificateExtensions.Add(
                new X509SubjectKeyIdentifierExtension(csr.PublicKey, false));
            using X509Certificate2 cert = csr.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddDays(1));

            var jwkWrite = Jwk.FromX509Certificate(cert, withPrivateKey: true);
            jwkWrite.Kid = cert.Thumbprint;
            jwkWrite.Use = JwkUseNames.Sig.ToArray();
            var jwkRead = Jwk.FromX509Certificate(cert, withPrivateKey: false);
            jwkRead.Kid = cert.Thumbprint;
            jwkRead.Use = JwkUseNames.Sig.ToArray();

            var jws = new JwsDescriptor
            {
                JwtId = "id",
                Issuer = "abc",
                Audience = "def",
                Algorithm = SignatureAlgorithm.RsaSha256,
                SigningKey = jwkWrite,
                Subject = "xyz",
                ExpirationTime = DateTime.UtcNow.AddDays(1),
            };
            jws.AddClaim("test", "value");

            var writer = new JwtWriter();
            var token = writer.WriteTokenString(jws);

            var reader = new JwtReader();
            var policy = new TokenValidationPolicyBuilder()
                .RequireIssuer("abc")
                .RequireAudience("def")
                .RequireClaim("jti")
                .RequireClaim("sub")
                .RequireSignature(new TestKeyProvider(jwkRead))
                .EnableLifetimeValidation()
                .Build();

            var result = reader.TryReadToken(token, policy);
            Assert.True(result.Succedeed);
        }

        [Theory]
        [InlineData("SHA512")] // only ECDsa+SHA512 supported via FromX509Certificate
        public void FromECDsaCertificateTest(string hashAlgorithmName)
        {
            using var ecdsaKey = ECDsa.Create();
            var csr = new CertificateRequest("cn=test", ecdsaKey, new HashAlgorithmName(hashAlgorithmName));
            csr.CertificateExtensions.Add(
                new X509BasicConstraintsExtension(false, false, 0, false));
            csr.CertificateExtensions.Add(
                new X509KeyUsageExtension(X509KeyUsageFlags.DigitalSignature | X509KeyUsageFlags.NonRepudiation, false));
            csr.CertificateExtensions.Add(
                new X509EnhancedKeyUsageExtension(
                    new OidCollection
                    {
                        new Oid("1.3.6.1.5.5.7.3.8")
                    },
                    true));
            csr.CertificateExtensions.Add(
                new X509SubjectKeyIdentifierExtension(csr.PublicKey, false));
            using X509Certificate2 cert = csr.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddDays(1));

            var jwkWrite = Jwk.FromX509Certificate(cert, withPrivateKey: true);
            jwkWrite.Kid = cert.Thumbprint;
            jwkWrite.Use = JwkUseNames.Sig.ToArray();
            var jwkRead = Jwk.FromX509Certificate(cert, withPrivateKey: false);
            jwkRead.Kid = cert.Thumbprint;
            jwkRead.Use = JwkUseNames.Sig.ToArray();

            var jws = new JwsDescriptor
            {
                JwtId = "id",
                Issuer = "abc",
                Audience = "def",
                Algorithm = SignatureAlgorithm.RsaSha256,
                SigningKey = jwkWrite,
                Subject = "xyz",
                ExpirationTime = DateTime.UtcNow.AddDays(1),
            };
            jws.AddClaim("test", "value");

            var writer = new JwtWriter();
            var token = writer.WriteTokenString(jws);

            var reader = new JwtReader();
            var policy = new TokenValidationPolicyBuilder()
                .RequireIssuer("abc")
                .RequireAudience("def")
                .RequireClaim("jti")
                .RequireClaim("sub")
                .RequireSignature(new TestKeyProvider(jwkRead))
                .EnableLifetimeValidation()
                .Build();

            var result = reader.TryReadToken(token, policy);
            Assert.True(result.Succedeed);
        }

        private class TestKeyProvider : IKeyProvider
        {
            private Jwk _jwkRead;

            public TestKeyProvider(Jwk jwkRead)
            {
                _jwkRead = jwkRead;
            }

            public Jwk[] GetKeys(JwtHeader header)
                => header.Kid == _jwkRead.Kid ? new[] { _jwkRead } : Array.Empty<Jwk>();
        }
#endif
    }
}
