using System.Security.Cryptography;
using System.Text;
using TechnitiumLibrary.Security.Cryptography;

namespace TechnitiumLibrary.Tests.TechnitiumLibrary.Security.Cryptography
{
    public class SignatureTests
    {
        [Fact]
        public void SignatureRoundTripsAndVerifiesWithCertificate()
        {
            using AsymmetricCryptoKey key = new AsymmetricCryptoKey(AsymmetricEncryptionAlgorithm.RSA, 1024);
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
            byte[] data = Encoding.UTF8.GetBytes("signed content");
            byte[] hash = SHA256.HashData(data);

            Signature signature = new Signature(hash, "SHA256", cert, key);
            using MemoryStream stream = new MemoryStream();
            signature.WriteTo(stream);
            stream.Position = 0;
            Signature parsed = new Signature(stream);

            Assert.Equal("SHA256", parsed.HashAlgorithm);
            Assert.Equal(AsymmetricEncryptionAlgorithm.RSA, parsed.SignatureAlgorithm);
            Assert.Equal(cert, parsed.SigningCertificate);
            Assert.True(parsed.Verify(hash, cert));
            Assert.True(parsed.Verify(new MemoryStream(data), [cert]));
            Assert.False(parsed.Verify(SHA256.HashData("other"u8.ToArray()), cert));
            Assert.Equal(signature, parsed);
            Assert.NotEqual(0, parsed.GetHashCode());
            Assert.StartsWith("<Signature>", parsed.ToString());
        }

        [Fact]
        public void SignatureConstructedFromStreamDataVerifies()
        {
            using AsymmetricCryptoKey key = new AsymmetricCryptoKey(AsymmetricEncryptionAlgorithm.RSA, 1024);
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
            byte[] data = Encoding.UTF8.GetBytes("signed content");

            Signature signature = new Signature(new MemoryStream(data), "SHA256", cert, key);

            Assert.True(signature.Verify(SHA256.HashData(data), cert));
            Assert.False(signature.Equals(null));
            Assert.False(signature.Equals("signature"));
        }

        [Fact]
        public void InvalidSignatureFormatThrows()
        {
            Assert.Throws<CryptoException>(() => new Signature(new MemoryStream([0, 1, 2])));
            Assert.Throws<CryptoException>(() => new Signature(new MemoryStream([.. Encoding.ASCII.GetBytes("SN"), 255])));
        }
    }
}
