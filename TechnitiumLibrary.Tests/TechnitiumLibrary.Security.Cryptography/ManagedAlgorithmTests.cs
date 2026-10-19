using System.Security.Cryptography;
using System.Text;
using TechnitiumLibrary.Security.Cryptography;

namespace TechnitiumLibrary.Tests.TechnitiumLibrary.Security.Cryptography
{
    public class ManagedAlgorithmTests
    {
        [Fact]
        public void Crc32MatchesKnownCheckValueAndCanBeReused()
        {
            using CRC32Managed crc32 = new CRC32Managed();
            byte[] input = Encoding.ASCII.GetBytes("123456789");

            byte[] hash = crc32.ComputeHash(input);
            crc32.Initialize();
            byte[] hashAfterReset = crc32.ComputeHash(input);

            Assert.Equal(Convert.FromHexString("CBF43926"), hash);
            Assert.Equal(hash, hashAfterReset);
            Assert.Equal(32, crc32.HashSize);
        }

        [Fact]
        public void Rc4EncryptorAndDecryptorRoundTripData()
        {
            byte[] key = Enumerable.Range(1, 32).Select(i => (byte)i).ToArray();
            byte[] iv = Enumerable.Range(33, 32).Select(i => (byte)i).ToArray();
            byte[] clearText = Encoding.UTF8.GetBytes("The quick brown fox jumps over the lazy dog.");
            byte[] cipherText = new byte[clearText.Length];
            byte[] decrypted = new byte[clearText.Length];

            using RC4Managed rc4 = new RC4Managed(key, iv);
            using ICryptoTransform encryptor = rc4.CreateEncryptor(key, iv);
            using ICryptoTransform decryptor = rc4.CreateDecryptor(key, iv);

            Assert.Equal(clearText.Length, encryptor.TransformBlock(clearText, 0, clearText.Length, cipherText, 0));
            Assert.Equal(clearText.Length, decryptor.TransformBlock(cipherText, 0, cipherText.Length, decrypted, 0));

            Assert.NotEqual(clearText, cipherText);
            Assert.Equal(clearText, decrypted);
            Assert.Empty(encryptor.TransformFinalBlock([], 0, 0));
            Assert.False(encryptor.CanReuseTransform);
            Assert.True(encryptor.CanTransformMultipleBlocks);
            Assert.Equal(8, encryptor.InputBlockSize);
            Assert.Equal(8, encryptor.OutputBlockSize);
        }

        [Fact]
        public void Rc4ConstructorsGenerateKeyAndIvForLegalKeySizes()
        {
            using RC4Managed defaultKeySize = new RC4Managed();
            using RC4Managed explicitKeySize = new RC4Managed(128);

            Assert.Equal(256, defaultKeySize.KeySize);
            Assert.Equal(32, defaultKeySize.Key.Length);
            Assert.Equal(32, defaultKeySize.IV.Length);
            Assert.Equal(128, explicitKeySize.KeySize);
            Assert.Equal(16, explicitKeySize.Key.Length);
            Assert.Equal(16, explicitKeySize.IV.Length);
        }
    }
}
