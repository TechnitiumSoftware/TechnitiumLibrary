using System.Security.Cryptography;
using System.Text;
using TechnitiumLibrary.Security.Cryptography;

namespace TechnitiumLibrary.Tests.TechnitiumLibrary.Security.Cryptography
{
    public class SymmetricCryptoKeyTests
    {
        [Theory]
        [InlineData(SymmetricEncryptionAlgorithm.DES, 64)]
        [InlineData(SymmetricEncryptionAlgorithm.RC2, 128)]
        [InlineData(SymmetricEncryptionAlgorithm.TripleDES, 192)]
        [InlineData(SymmetricEncryptionAlgorithm.Rijndael, 256)]
        public void GeneratedKeyEncryptsDecryptsAndSerializes(SymmetricEncryptionAlgorithm algorithm, int keySize)
        {
            using SymmetricCryptoKey key = new SymmetricCryptoKey(algorithm, keySize, PaddingMode.PKCS7);
            byte[] clearText = Encoding.UTF8.GetBytes("clear text for " + algorithm);
            using MemoryStream cipherText = new MemoryStream();
            using MemoryStream decrypted = new MemoryStream();

            key.Encrypt(new MemoryStream(clearText), cipherText);
            byte[] encrypted = cipherText.ToArray();
            key.Decrypt(new MemoryStream(encrypted), decrypted);

            Assert.Equal(clearText, decrypted.ToArray());
            Assert.Equal(algorithm, key.Algorithm);
            Assert.Equal(keySize, key.KeySize);
            Assert.True(key.BlockSize > 0);

            using MemoryStream serialized = new MemoryStream();
            key.WriteTo(serialized);
            serialized.Position = 0;
            using SymmetricCryptoKey parsed = new SymmetricCryptoKey(serialized);

            using MemoryStream parsedCipherText = new MemoryStream();
            using MemoryStream parsedDecrypted = new MemoryStream();
            parsed.Encrypt(new MemoryStream(clearText), parsedCipherText);
            parsed.Decrypt(new MemoryStream(parsedCipherText.ToArray()), parsedDecrypted);

            Assert.Equal(clearText, parsedDecrypted.ToArray());
            Assert.Equal(algorithm, parsed.Algorithm);
            Assert.Equal(key.IV.Length, parsed.IV.Length);
        }

        [Fact]
        public void ExplicitKeyAndIvCanBeUsedWithCryptoStreams()
        {
            byte[] keyBytes = Enumerable.Range(1, 32).Select(i => (byte)i).ToArray();
            byte[] iv = Enumerable.Range(33, 16).Select(i => (byte)i).ToArray();
            byte[] clearText = Encoding.UTF8.GetBytes("stream encryption");
            using SymmetricCryptoKey key = new SymmetricCryptoKey(SymmetricEncryptionAlgorithm.Rijndael, keyBytes, iv, PaddingMode.PKCS7);
            using MemoryStream cipherText = new MemoryStream();

            using (CryptoStream writer = key.GetCryptoStreamWriter(cipherText))
            {
                writer.Write(clearText);
                writer.FlushFinalBlock();
            }

            using CryptoStream reader = key.GetCryptoStreamReader(new MemoryStream(cipherText.ToArray()));
            using MemoryStream decrypted = new MemoryStream();
            reader.CopyTo(decrypted);

            Assert.Equal(clearText, decrypted.ToArray());
        }

        [Fact]
        public void GenerateIvChangesIvAndInvalidFormatThrows()
        {
            using SymmetricCryptoKey key = new SymmetricCryptoKey(SymmetricEncryptionAlgorithm.Rijndael, 256, PaddingMode.PKCS7);
            byte[] oldIv = key.IV.ToArray();

            key.GenerateIV();

            Assert.NotEqual(oldIv, key.IV);
            Assert.Throws<CryptoException>(() => new SymmetricCryptoKey(new MemoryStream([0, 1, 2])));
            Assert.Throws<CryptoException>(() => new SymmetricCryptoKey(new MemoryStream([.. Encoding.ASCII.GetBytes("SK"), 255])));
        }
    }
}
