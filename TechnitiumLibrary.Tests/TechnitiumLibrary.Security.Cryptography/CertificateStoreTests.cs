using TechnitiumLibrary.Security.Cryptography;

namespace TechnitiumLibrary.Tests.TechnitiumLibrary.Security.Cryptography
{
    public class CertificateStoreTests
    {
        [Fact]
        public void CertificateStoreRoundTripsPlainAndPasswordProtected()
        {
            using AsymmetricCryptoKey key = new AsymmetricCryptoKey(AsymmetricEncryptionAlgorithm.RSA, 1024);
            Certificate cert = CreateCertificate(key);
            using CertificateStore plainStore = new CertificateStore(cert, key);
            using MemoryStream plainStream = new MemoryStream();

            plainStore.WriteTo(plainStream);
            plainStream.Position = 0;
            using CertificateStore parsedPlain = new CertificateStore(plainStream);

            Assert.Equal(cert, parsedPlain.Certificate);
            Assert.Equal(key.Algorithm, parsedPlain.PrivateKey.Algorithm);

            using CertificateStore protectedStore = new CertificateStore(cert, key, "password");
            using MemoryStream protectedStream = new MemoryStream();
            protectedStore.WriteTo(protectedStream);

            using CertificateStore parsedProtected = new CertificateStore(new MemoryStream(protectedStream.ToArray()), "password");

            Assert.Equal(cert, parsedProtected.Certificate);
            Assert.Equal(key.Algorithm, parsedProtected.PrivateKey.Algorithm);
            Assert.Throws<CryptoException>(() => new CertificateStore(new MemoryStream(protectedStream.ToArray()), "wrong"));
        }

        [Fact]
        public void CertificateStoreFileConstructorRoundTrips()
        {
            using AsymmetricCryptoKey key = new AsymmetricCryptoKey(AsymmetricEncryptionAlgorithm.RSA, 1024);
            Certificate cert = CreateCertificate(key);
            using CertificateStore store = new CertificateStore(cert, key, "password");
            string file = Path.Combine(Path.GetTempPath(), "certificate-store-" + Guid.NewGuid() + ".bin");

            try
            {
                store.SaveAs(file);
                using CertificateStore parsed = new CertificateStore(file, "password");
                Assert.Equal(cert, parsed.Certificate);
            }
            finally
            {
                if (File.Exists(file))
                    File.Delete(file);
            }
        }

        [Fact]
        public void InvalidCertificateStoreFormatThrows()
        {
            Assert.Throws<InvalidCryptoContainerException>(() => new CertificateStore(new MemoryStream([.. System.Text.Encoding.ASCII.GetBytes("CC"), 0, 0, 1])));
            Assert.Throws<CryptoException>(() => new CertificateStore(new MemoryStream([.. System.Text.Encoding.ASCII.GetBytes("CC"), 0, .. System.Text.Encoding.ASCII.GetBytes("CS"), 255])));
        }

        private static Certificate CreateCertificate(AsymmetricCryptoKey key)
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
            cert.SelfSign("SHA256", key, null);
            return cert;
        }
    }
}
