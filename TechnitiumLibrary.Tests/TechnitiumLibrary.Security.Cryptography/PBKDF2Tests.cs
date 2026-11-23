using System.Security.Cryptography;
using System.Text;
using TechnitiumLibrary.Security.Cryptography;

namespace TechnitiumLibrary.Tests.TechnitiumLibrary.Security.Cryptography
{
    public class PBKDF2Tests
    {
        [Theory]
        [InlineData("password", "salt", 1, 20, "0C60C80F961F0E71F3A9B524AF6012062FE037A6")]
        [InlineData("password", "salt", 2, 20, "EA6C014DC72D6F8CCD1ED92ACE1D41F0D8DE8957")]
        [InlineData("password", "salt", 4096, 20, "4B007901B765489ABEAD49D926F721D065A429C1")]
        public void HmacSha1MatchesRfc6070Vectors(string password, string salt, int iterations, int length, string expectedHex)
        {
            using PBKDF2 pbkdf2 = PBKDF2.CreateHMACSHA1(password, Encoding.ASCII.GetBytes(salt), iterations);

            byte[] actual = pbkdf2.GetBytes(length);

            Assert.Equal(Convert.FromHexString(expectedHex), actual);
            Assert.Equal(iterations, pbkdf2.IterationCount);
            Assert.Equal(Encoding.ASCII.GetBytes(salt), pbkdf2.Salt);
        }

        [Fact]
        public void HmacSha256MatchesFrameworkImplementation()
        {
            byte[] salt = [1, 2, 3, 4, 5, 6, 7, 8];
            using PBKDF2 pbkdf2 = PBKDF2.CreateHMACSHA256("password", salt, 1000);

            byte[] actual = pbkdf2.GetBytes(48);
            byte[] expected = Rfc2898DeriveBytes.Pbkdf2("password", salt, 1000, HashAlgorithmName.SHA256, 48);

            Assert.Equal(expected, actual);
        }

        [Fact]
        public void RandomSaltFactoriesCreateRequestedSaltLength()
        {
            using PBKDF2 fromString = PBKDF2.CreateHMACSHA1("password", saltLength: 16, iterationCount: 2);
            using PBKDF2 fromBytes = PBKDF2.CreateHMACSHA256(Encoding.UTF8.GetBytes("password"), saltLength: 24, iterationCount: 3);

            Assert.Equal(16, fromString.Salt.Length);
            Assert.Equal(24, fromBytes.Salt.Length);
            Assert.Equal(20, fromString.GetBytes(20).Length);
            Assert.Equal(32, fromBytes.GetBytes(32).Length);

            fromString.Reset();
            fromBytes.Reset();
        }
    }
}
