using System.Security.Cryptography;
using System.Text;
using TechnitiumLibrary.Security.Cryptography;

namespace TechnitiumLibrary.Tests.TechnitiumLibrary.Security.Cryptography
{
    public class AsymmetricCryptoKeyTests
    {
        [Fact]
        public void RsaKeyEncryptsDecryptsSignsVerifiesAndSerializes()
        {
            byte[] clearText = Encoding.UTF8.GetBytes("secret");
            byte[] data = Encoding.UTF8.GetBytes("signed data");
            byte[] hash = SHA256.HashData(data);

            using AsymmetricCryptoKey key = new AsymmetricCryptoKey(AsymmetricEncryptionAlgorithm.RSA, 1024);
            byte[] cipherText = key.Encrypt(clearText);
            byte[] signature = key.Sign(hash, "SHA256");

            Assert.Equal(AsymmetricEncryptionAlgorithm.RSA, key.Algorithm);
            Assert.Equal(clearText, key.Decrypt(cipherText));
            Assert.True(key.Verify(hash, signature, "SHA256"));
            Assert.True(key.Verify(new MemoryStream(data), signature, "SHA256"));
            Assert.False(key.Verify(SHA256.HashData("other"u8.ToArray()), signature, "SHA256"));
            Assert.NotNull(key.GetRSAPublicKey().Modulus);

            string publicKey = key.GetPublicKey();
            Assert.Equal(clearText, AsymmetricCryptoKey.Decrypt(AsymmetricCryptoKey.Encrypt(clearText, AsymmetricEncryptionAlgorithm.RSA, publicKey), AsymmetricEncryptionAlgorithm.RSA, keyXml(key)));
            Assert.True(AsymmetricCryptoKey.Verify(hash, AsymmetricCryptoKey.Sign(hash, "SHA256", AsymmetricEncryptionAlgorithm.RSA, keyXml(key)), "SHA256", AsymmetricEncryptionAlgorithm.RSA, publicKey));
            Assert.True(AsymmetricCryptoKey.Verify(new MemoryStream(data), AsymmetricCryptoKey.Sign(new MemoryStream(data), "SHA256", AsymmetricEncryptionAlgorithm.RSA, keyXml(key)), "SHA256", AsymmetricEncryptionAlgorithm.RSA, publicKey));

            using MemoryStream stream = new MemoryStream();
            key.WriteTo(stream);
            stream.Position = 0;
            using AsymmetricCryptoKey parsed = new AsymmetricCryptoKey(stream);

            Assert.Equal(clearText, parsed.Decrypt(parsed.Encrypt(clearText)));
            Assert.True(parsed.Verify(hash, parsed.Sign(hash, "SHA256"), "SHA256"));
        }

        [Fact]
        public void CreateUsingImportsRsaParameters()
        {
            using RSA rsa = RSA.Create(1024);
            using AsymmetricCryptoKey key = AsymmetricCryptoKey.CreateUsing(rsa.ExportParameters(true));

            byte[] clearText = Encoding.UTF8.GetBytes("secret");

            Assert.Equal(AsymmetricEncryptionAlgorithm.RSA, key.Algorithm);
            Assert.Equal(clearText, key.Decrypt(key.Encrypt(clearText)));
        }

        [Fact]
        public void UnsupportedAlgorithmsAndInvalidFormatsThrow()
        {
            using AsymmetricCryptoKey dsa = new AsymmetricCryptoKey(AsymmetricEncryptionAlgorithm.DSA, 1024);

            Assert.Throws<NotImplementedException>(() => new AsymmetricCryptoKey(AsymmetricEncryptionAlgorithm.Unknown, 1024));
            Assert.Throws<NotImplementedException>(() => AsymmetricCryptoKey.Encrypt([1], AsymmetricEncryptionAlgorithm.DSA, dsa.GetPublicKey()));
            Assert.Throws<NotImplementedException>(() => AsymmetricCryptoKey.Decrypt([1], AsymmetricEncryptionAlgorithm.DSA, dsa.GetPublicKey()));
            Assert.Throws<CryptoException>(() => dsa.GetRSAPublicKey());
            Assert.Throws<CryptoException>(() => new AsymmetricCryptoKey(new MemoryStream([0, 1, 2])));
            Assert.Throws<CryptoException>(() => new AsymmetricCryptoKey(new MemoryStream([.. Encoding.ASCII.GetBytes("AK"), 255])));
        }

        private static string keyXml(AsymmetricCryptoKey key)
        {
            using MemoryStream stream = new MemoryStream();
            key.WriteTo(stream);
            stream.Position = 0;
            using BinaryReader reader = new BinaryReader(stream);
            _ = reader.ReadBytes(4);
            ushort length = reader.ReadUInt16();
            return Encoding.ASCII.GetString(reader.ReadBytes(length));
        }
    }
}
