using TechnitiumLibrary.Security.Cryptography;

namespace TechnitiumLibrary.Tests.TechnitiumLibrary.Security.Cryptography
{
    public class RevocationCertificateTests
    {
        [Fact]
        public void RevocationCertificateRoundTripsAndValidates()
        {
            using AsymmetricCryptoKey key = new AsymmetricCryptoKey(AsymmetricEncryptionAlgorithm.RSA, 1024);
            Certificate cert = CreateRootCertificate(key);
            RevocationCertificate revocation = new RevocationCertificate(cert, "SHA256", key);
            using MemoryStream stream = new MemoryStream();

            revocation.WriteTo(stream);
            stream.Position = 0;
            RevocationCertificate parsed = new RevocationCertificate(stream);

            Assert.Equal(cert.SerialNumber, parsed.SerialNumber);
            Assert.Equal("SHA256", parsed.HashAlgorithm);
            Assert.NotEmpty(parsed.Signature);
            Assert.True(parsed.RevokedOnUTC <= DateTime.UtcNow.AddSeconds(1));
        }

        [Fact]
        public void RevocationCertificateReturnsFalseForInvalidSignature()
        {
            using AsymmetricCryptoKey key = new AsymmetricCryptoKey(AsymmetricEncryptionAlgorithm.RSA, 1024);
            Certificate cert = CreateRootCertificate(key);
            RevocationCertificate revocation = new RevocationCertificate(cert, "SHA256", key);

            revocation.Signature[0] ^= 0xff;

            Assert.False(revocation.IsValid(cert));
        }

        [Fact]
        public void RevocationServerResponsesCanBeWritten()
        {
            using AsymmetricCryptoKey key = new AsymmetricCryptoKey(AsymmetricEncryptionAlgorithm.RSA, 1024);
            Certificate cert = CreateRootCertificate(key);
            RevocationCertificate revocation = new RevocationCertificate(cert, "SHA256", key);
            using MemoryStream found = new MemoryStream();
            using MemoryStream notFound = new MemoryStream();

            revocation.WriteFoundServerResponseTo(found);
            RevocationCertificate.WriteNotFoundServerResponseTo(notFound);

            Assert.Equal(1, found.ToArray()[0]);
            Assert.Equal(0, notFound.ToArray()[0]);
            found.Position = 1;
            RevocationCertificate parsed = new RevocationCertificate(found);
            Assert.Equal(cert.SerialNumber, parsed.SerialNumber);
        }

        [Fact]
        public void RevocationCertificateRejectsMismatchedSerialAndInvalidFormat()
        {
            using AsymmetricCryptoKey key = new AsymmetricCryptoKey(AsymmetricEncryptionAlgorithm.RSA, 1024);
            Certificate cert = CreateRootCertificate(key);
            Certificate other = new Certificate(
                CertificateType.RootCA,
                "other",
                new CertificateProfile("other"),
                CertificateCapability.SignCACertificate,
                DateTime.UtcNow.AddMinutes(-1),
                DateTime.UtcNow.AddDays(1),
                key.Algorithm,
                key.GetPublicKey());
            other.SelfSign("SHA256", key, null);
            RevocationCertificate revocation = new RevocationCertificate(cert, "SHA256", key);

            Assert.Throws<CryptoException>(() => revocation.IsValid(other));
            Assert.Throws<InvalidCertificateException>(() => new RevocationCertificate(new MemoryStream([0, 1, 2])));
            Assert.Throws<InvalidCertificateException>(() => new RevocationCertificate(new MemoryStream([.. System.Text.Encoding.ASCII.GetBytes("RC"), 255])));
            Assert.Throws<CryptoException>(() => RevocationCertificate.IsRevoked(other, out _));
        }

        private static Certificate CreateRootCertificate(AsymmetricCryptoKey key)
        {
            Certificate cert = new Certificate(
                CertificateType.RootCA,
                "root",
                new CertificateProfile("root"),
                CertificateCapability.SignCACertificate,
                DateTime.UtcNow.AddMinutes(-1),
                DateTime.UtcNow.AddDays(1),
                key.Algorithm,
                key.GetPublicKey());
            cert.SelfSign("SHA256", key, new Uri("https://ca.example.test/revoke"));
            return cert;
        }
    }
}
