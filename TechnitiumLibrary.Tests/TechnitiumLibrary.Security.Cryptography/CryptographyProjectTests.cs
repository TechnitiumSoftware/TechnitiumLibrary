using System.IO;
using System.Security.Cryptography;
using TechnitiumLibrary.Security.Cryptography;

namespace TechnitiumLibrary.Tests.TechnitiumLibrary.Security.Cryptography
{
    public class CryptographyProjectTests
    {
        [Fact]
        public void PEMFormat_RsaPrivateKeyRoundtrip()
        {
            using RSA rsa = RSA.Create(1024);
            RSAParameters expected = rsa.ExportParameters(true);
            using MemoryStream stream = new MemoryStream();

            PEMFormat.WriteRSAPrivateKey(expected, stream);
            stream.Position = 0;
            RSAParameters actual = PEMFormat.ReadRSAPrivateKey(stream);

            Assert.Equal(expected.Modulus, actual.Modulus);
            Assert.Equal(expected.Exponent, actual.Exponent);
            Assert.Equal(expected.D, actual.D);
            Assert.Equal(expected.P, actual.P);
            Assert.Equal(expected.Q, actual.Q);
        }

        [Fact]
        public void PEMFormat_RsaPublicKeyRoundtrip()
        {
            using RSA rsa = RSA.Create(1024);
            RSAParameters expected = rsa.ExportParameters(false);
            using MemoryStream stream = new MemoryStream();

            PEMFormat.WriteRSAPublicKey(expected, stream);
            stream.Position = 0;
            RSAParameters actual = PEMFormat.ReadRSAPublicKey(stream);

            Assert.Equal(expected.Modulus, actual.Modulus);
            Assert.Equal(expected.Exponent, actual.Exponent);
        }

        [Fact]
        public void PEMFormat_InvalidHeaderThrows()
        {
            using MemoryStream stream = new MemoryStream(System.Text.Encoding.ASCII.GetBytes("bad pem"));

            Assert.Throws<IOException>(() => PEMFormat.ReadRSAPublicKey(stream));
        }
    }
}
