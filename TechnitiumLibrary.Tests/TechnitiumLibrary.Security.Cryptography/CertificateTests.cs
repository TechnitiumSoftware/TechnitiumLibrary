using System.Security.Cryptography;
using TechnitiumLibrary.Security.Cryptography;

namespace TechnitiumLibrary.Tests.TechnitiumLibrary.Security.Cryptography
{
    public class CertificateTests
    {
        [Fact]
        public void RootCertificateSelfSignsSerializesAndVerifies()
        {
            using AsymmetricCryptoKey rootKey = new AsymmetricCryptoKey(AsymmetricEncryptionAlgorithm.RSA, 1024);
            Certificate root = CreateCertificate(CertificateType.RootCA, "root", CertificateCapability.SignCACertificate, rootKey);

            root.SelfSign("SHA256", rootKey, new Uri("https://ca.example.test/revoke"));

            Assert.True(root.IsSigned());
            Assert.False(root.HasExpired());
            Assert.Equal(CertificateType.RootCA, root.Type);
            Assert.Equal("root", root.SerialNumber);
            Assert.Equal(CertificateCapability.SignCACertificate, root.Capability);
            Assert.Equal(AsymmetricEncryptionAlgorithm.RSA, root.PublicKeyEncryptionAlgorithm);
            Assert.Equal(new Uri("https://ca.example.test/revoke"), root.RevocationURL);
            Assert.Same(root.GetHash("SHA256"), root.GetHash("SHA256"));

            root.Verify([root]);

            Certificate parsed = RoundTrip(root);
            Assert.Equal(root, parsed);
            Assert.True(parsed.IssuerSignature.Verify(parsed.GetHash(parsed.IssuerSignature.HashAlgorithm), parsed));
        }

        [Fact]
        public void CaAndUserCertificatesVerifyThroughTrustedRoot()
        {
            using AsymmetricCryptoKey rootKey = new AsymmetricCryptoKey(AsymmetricEncryptionAlgorithm.RSA, 1024);
            using AsymmetricCryptoKey caKey = new AsymmetricCryptoKey(AsymmetricEncryptionAlgorithm.RSA, 1024);
            using AsymmetricCryptoKey userKey = new AsymmetricCryptoKey(AsymmetricEncryptionAlgorithm.RSA, 1024);
            Certificate root = CreateCertificate(CertificateType.RootCA, "root", CertificateCapability.SignCACertificate, rootKey);
            Certificate ca = CreateCertificate(CertificateType.CA, "ca", CertificateCapability.SignAnyUserCertificate, caKey);
            Certificate user = CreateCertificate(CertificateType.User, "user", CertificateCapability.UserAuthentication, userKey);
            root.SelfSign("SHA256", rootKey, new Uri("https://ca.example.test/revoke"));

            ca.Sign("SHA256", root, rootKey, new Uri("https://ca.example.test/revoke"));
            user.Sign("SHA256", ca, caKey, new Uri("https://ca.example.test/revoke"));

            ca.Verify([root]);
            user.Verify([root]);
            user.VerifyRevocationList(timeout: 1);

            Assert.Equal(root, ca.IssuerSignature.SigningCertificate);
            Assert.Equal(ca, user.IssuerSignature.SigningCertificate);
            Assert.NotEqual(root, user);
            Assert.False(user.Equals(null));
            Assert.False(user.Equals("certificate"));
            Assert.True(user.Equals(user));
            Assert.NotEqual(0, user.GetHashCode());
        }

        [Fact]
        public void CertificateValidationRejectsInvalidDatesAndCapabilities()
        {
            using AsymmetricCryptoKey rootKey = new AsymmetricCryptoKey(AsymmetricEncryptionAlgorithm.RSA, 1024);
            using AsymmetricCryptoKey userKey = new AsymmetricCryptoKey(AsymmetricEncryptionAlgorithm.RSA, 1024);
            Certificate root = CreateCertificate(CertificateType.RootCA, "root", CertificateCapability.SignCACertificate, rootKey);
            Certificate badRoot = CreateCertificate(CertificateType.RootCA, "bad-root", CertificateCapability.UserAuthentication, rootKey);
            Certificate user = CreateCertificate(CertificateType.User, "user", CertificateCapability.UserAuthentication, userKey);
            root.SelfSign("SHA256", rootKey, null);
            badRoot.SelfSign("SHA256", rootKey, null);

            Assert.Throws<CryptoException>(() => new Certificate(CertificateType.User, "bad", new CertificateProfile("bad"), CertificateCapability.UserAuthentication, DateTime.UtcNow.AddDays(1), DateTime.UtcNow, AsymmetricEncryptionAlgorithm.RSA, userKey.GetPublicKey()));
            Assert.Throws<CryptoException>(() => root.Sign("SHA256", root, rootKey, null));
            Assert.Throws<CryptoException>(() => user.Sign("SHA256", user, userKey, null));
            Assert.Throws<InvalidCertificateException>(() => badRoot.Verify([badRoot]));
            Assert.Throws<InvalidCertificateException>(() => root.Verify([]));
        }

        [Fact]
        public void CertificateInvalidFormatsThrow()
        {
            Assert.Throws<InvalidCertificateException>(() => new Certificate(new MemoryStream([0, 1, 2])));
            Assert.Throws<InvalidCertificateException>(() => new Certificate(new MemoryStream([.. System.Text.Encoding.ASCII.GetBytes("CE"), 255])));
        }

        private static Certificate CreateCertificate(CertificateType type, string serial, CertificateCapability capability, AsymmetricCryptoKey key)
        {
            return new Certificate(
                type,
                serial,
                new CertificateProfile(serial, CertificateProfileType.Individual, new System.Net.Mail.MailAddress(serial + "@example.test")),
                capability,
                DateTime.UtcNow.AddMinutes(-1),
                DateTime.UtcNow.AddDays(30),
                key.Algorithm,
                key.GetPublicKey());
        }

        private static Certificate RoundTrip(Certificate certificate)
        {
            using MemoryStream stream = new MemoryStream();
            certificate.WriteTo(stream);
            stream.Position = 0;
            return new Certificate(stream);
        }
    }
}
